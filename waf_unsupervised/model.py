from __future__ import annotations

import math
import os
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict
from typing import Any, Iterator, Literal, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM

from .autoencoder import AutoencoderAnomalyDetector
from .config import ModelConfig, OcsvmBackend
from .features import build_feature_pipeline, transform_features


ModelTypeLiteral = Literal["isolation_forest", "one_class_svm", "autoencoder"]


def _gamma_for_thundersvm(gamma: Union[str, float], X: np.ndarray) -> float:
    """将 sklearn 风格 gamma（scale/auto）转为 ThunderSVM 所需的 float。"""
    X = np.asarray(X, dtype=np.float64)
    n_features = X.shape[1]
    if isinstance(gamma, str):
        g = gamma.lower()
        if g == "scale":
            x_var = float(np.var(X))
            if x_var > 0:
                return 1.0 / (n_features * x_var)
            return 1.0
        if g == "auto":
            return 1.0 / n_features
        raise ValueError(f"ThunderSVM 不支持 gamma={gamma!r}，请使用数值或 scale/auto")
    return float(gamma)


class ThunderOneClassSVMAdapter:
    """包装 thundersvm.OneClassSVM，使 predict/decision_function 与 sklearn 一致。"""

    def __init__(self, inner: Any):
        self._inner = inner

    def fit(self, X: np.ndarray, y: Any = None) -> "ThunderOneClassSVMAdapter":
        X = np.asarray(X, dtype=np.float64, order="C")
        self._inner.fit(X, y)
        return self

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        X = np.asarray(X, dtype=np.float64, order="C")
        d = self._inner.decision_function(X)
        arr = np.asarray(d, dtype=np.float64)
        if arr.ndim > 1:
            arr = arr.ravel()
        return arr

    def predict(self, X: np.ndarray) -> np.ndarray:
        s = self.decision_function(X)
        out = np.ones(s.shape[0], dtype=np.int32)
        out[s < 0] = -1
        return out

    def __getstate__(self) -> dict[str, Any]:
        return {"_inner": self._inner}

    def __setstate__(self, state: dict[str, Any]) -> None:
        self._inner = state["_inner"]


def _try_thundersvm_one_class_svm():
    try:
        from thundersvm import OneClassSVM as ThunderOneClassSVM  # type: ignore[import-untyped]
    except ImportError as e:
        raise ImportError(
            "未安装 thundersvm 或 CUDA 库不匹配。请先安装与显卡驱动匹配的版本，例如：\n"
            "  pip install thundersvm\n"
            "详见 https://github.com/Xtra-Computing/thundersvm 说明。"
        ) from e
    return ThunderOneClassSVM


def _train_master_progress_enabled() -> bool:
    v = os.environ.get("WAF_TRAIN_PROGRESS", "").strip().lower()
    if v in ("0", "false", "no", "off"):
        return False
    if v in ("1", "true", "yes", "on"):
        return True
    return sys.stderr.isatty()


def _estimate_model_fit_seconds(
    model_type: str,
    n_samples: int,
    n_features: int,
    feature_phase_seconds: float,
    *,
    ocsvm_backend: OcsvmBackend = "sklearn",
    ae_epochs: int = 30,
    ae_batch_size: int = 2048,
) -> float:
    """
    粗估无监督模型 fit 耗时（仅用于进度展示，与实际硬件/数据分布有关）。
    """
    ns = max(int(n_samples), 1)
    nf = max(int(n_features), 1)
    feat = max(float(feature_phase_seconds), 1.0)
    if model_type == "one_class_svm":
        base = max(
            120.0,
            80.0 + (ns / 150_000.0) * 600.0 * math.sqrt(nf / 48.0),
            feat * 2.5,
        )
        if ocsvm_backend == "thundersvm":
            return max(25.0, base * 0.22 + 25.0)
        return base
    if model_type == "isolation_forest":
        return max(15.0, 25.0 + (ns / 900_000.0) * 100.0, feat * 0.25)
    if model_type == "autoencoder":
        ep = max(int(ae_epochs), 1)
        bs = max(int(ae_batch_size), 1)
        steps_per_ep = max(1, (ns + bs - 1) // bs)
        # 粗估：每 step 与特征维数弱相关
        step_cost = 0.0012 * math.sqrt(nf / 48.0)
        return max(30.0, feat * 0.2 + ep * steps_per_ep * step_cost * 800.0)
    return max(60.0, feat)


@contextmanager
def _model_fit_stderr_progress(
    estimated_seconds: float,
    model_name: str,
    *,
    enabled: bool,
) -> Iterator[None]:
    """
    在 sklearn model.fit 阻塞期间，用 stderr + \\r 周期刷新（不依赖 tqdm），
    避免嵌套 tqdm / 线程里改 pbar.n 在 Windows 终端不显示的问题。

    百分比仅为基于「粗估耗时」的示意，硬顶 97%：sklearn 未回调真实进度，
    长时间停在 97% 通常表示仍在计算（OneClassSVM 大数据上极慢），不是界面卡死。
    """
    if not enabled:
        yield
        return

    stop = threading.Event()
    start = time.perf_counter()
    est = max(float(estimated_seconds), 5.0)
    width = 40
    cap_frac = 0.97

    def _tick() -> None:
        while True:
            elapsed = time.perf_counter() - start
            if elapsed <= est:
                frac = min(cap_frac, 1.0 - math.exp(-elapsed / est))
                rem = est - elapsed
                tail = f"{frac * 100:5.1f}% 已用 {elapsed:.0f}s 估剩余 ~{rem:.0f}s"
            else:
                frac = cap_frac
                over = elapsed - est
                tail = (
                    f"{cap_frac * 100:5.1f}% 已用 {elapsed:.0f}s "
                    f"已超粗估 {over:.0f}s·仍在计算(非卡死)"
                )
            filled = int(width * frac)
            bar = "#" * filled + "-" * (width - filled)
            line = f"\r② 拟合 {model_name} |{bar}| {tail}"
            pad = max(0, 160 - len(line))
            sys.stderr.write(line + (" " * pad))
            sys.stderr.flush()
            if stop.wait(0.25):
                break

    th = threading.Thread(target=_tick, daemon=True)
    th.start()
    try:
        yield
    finally:
        stop.set()
        th.join(timeout=3.0)
        total_elapsed = time.perf_counter() - start
        done_bar = "#" * width
        sys.stderr.write(
            f"\r② 拟合 {model_name} |{done_bar}| 100.0% 完成 {total_elapsed:.1f}s\n"
        )
        sys.stderr.flush()


@contextmanager
def _feature_phase_progress(enabled: bool) -> Iterator[object]:
    """仅阶段①特征工程一条 tqdm，避免与阶段②的 stderr 进度冲突。"""
    if not enabled:
        yield None
        return
    try:
        from tqdm.auto import tqdm
    except ImportError:
        yield None
        return

    pbar = tqdm(
        total=1,
        desc="① 特征工程",
        unit="轮",
        dynamic_ncols=True,
        file=sys.stderr,
        bar_format="{l_bar}{bar}| {postfix}",
    )
    try:
        yield pbar
    finally:
        pbar.close()


class WAFUnsupervisedModel:
    """
    封装特征工程 + 无监督模型（孤立森林 / One-Class SVM / MLP 自编码器）。
    """

    def __init__(self, config: ModelConfig):
        self.config = config
        self.pipeline = None  # 特征工程 Pipeline
        self.model = None  # 无监督模型

    def _build_isolation_forest(self) -> IsolationForest:
        return IsolationForest(
            contamination=self.config.contamination,
            random_state=self.config.random_state,
            n_estimators=200,
            n_jobs=-1,
        )

    def _build_one_class_svm(self, X_train: np.ndarray) -> object:
        if self.config.ocsvm_backend == "sklearn":
            return OneClassSVM(
                kernel=self.config.ocsvm_kernel,
                nu=self.config.ocsvm_nu,
                gamma=self.config.ocsvm_gamma,
            )
        ThunderOC = _try_thundersvm_one_class_svm()
        gamma_f = _gamma_for_thundersvm(self.config.ocsvm_gamma, X_train)
        inner = ThunderOC(
            kernel=self.config.ocsvm_kernel,
            nu=float(self.config.ocsvm_nu),
            gamma=gamma_f,
            gpu_id=int(self.config.thundersvm_gpu_id),
        )
        return ThunderOneClassSVMAdapter(inner)

    def _build_autoencoder(self) -> AutoencoderAnomalyDetector:
        return AutoencoderAnomalyDetector(
            hidden_dim=self.config.ae_hidden_dim,
            latent_dim=self.config.ae_latent_dim,
            epochs=self.config.ae_epochs,
            batch_size=self.config.ae_batch_size,
            lr=self.config.ae_lr,
            mse_percentile=self.config.ae_mse_percentile,
            max_train_samples=self.config.ae_max_train_samples,
            random_state=self.config.random_state,
            decision_threshold=self.config.decision_threshold,
            device=self.config.ae_device,
            loss_alpha=self.config.ae_loss_alpha,
            loss_beta=self.config.ae_loss_beta,
            input_dropout=self.config.ae_input_dropout,
            binary_flip_prob=self.config.ae_binary_flip_prob,
        )

    def _model_display_name(self) -> str:
        if self.config.model_type == "one_class_svm":
            if self.config.ocsvm_backend == "thundersvm":
                return "OneClassSVM(ThunderSVM-GPU)"
            return "OneClassSVM"
        if self.config.model_type == "autoencoder":
            return "Autoencoder(MLP)"
        if self.model is not None:
            return type(self.model).__name__
        return "model"

    def fit(
        self,
        df_train: pd.DataFrame,
        label_column: str | None = None,
    ) -> "WAFUnsupervisedModel":
        """
        使用仅包含“正常”流量的数据进行训练。
        """
        show_train = _train_master_progress_enabled()
        self.pipeline, _ = build_feature_pipeline(df_train, label_column=label_column)
        src = df_train.drop(columns=[label_column]) if label_column and label_column in df_train.columns else df_train

        with _feature_phase_progress(show_train) as phase_bar:
            t_feat0 = time.perf_counter()
            if show_train:
                try:
                    from tqdm.auto import tqdm

                    tqdm.write(
                        f"[INFO] ① 特征工程 pipeline.fit_transform（{len(src):,} 条）…",
                        file=sys.stderr,
                    )
                except Exception:
                    print(f"[INFO] ① 特征工程 pipeline.fit_transform（{len(src):,} 条）…", flush=True)

            X_train = self.pipeline.fit_transform(src)
            dt_feat = time.perf_counter() - t_feat0
            if show_train:
                try:
                    from tqdm.auto import tqdm

                    tqdm.write(f"[INFO] ① 完成，用时 {dt_feat:.1f}s", file=sys.stderr)
                except Exception:
                    print(f"[INFO] ① 完成，用时 {dt_feat:.1f}s", flush=True)
            if phase_bar is not None:
                phase_bar.set_postfix_str(f"用时 {dt_feat:.0f}s")
                phase_bar.update(1)

        n_samples, n_features = int(X_train.shape[0]), int(X_train.shape[1])
        eta_fit = _estimate_model_fit_seconds(
            self.config.model_type,
            n_samples,
            n_features,
            dt_feat,
            ocsvm_backend=self.config.ocsvm_backend,
            ae_epochs=self.config.ae_epochs,
            ae_batch_size=self.config.ae_batch_size,
        )
        if self.config.model_type == "isolation_forest":
            self.model = self._build_isolation_forest()
        elif self.config.model_type == "one_class_svm":
            self.model = self._build_one_class_svm(X_train)
        elif self.config.model_type == "autoencoder":
            self.model = self._build_autoencoder()
            # 从预处理器中识别连续/二值维度分区，供混合损失使用
            cont_dim, bin_dim = self._infer_feature_partition()
            self.model.set_feature_partition(cont_dim=cont_dim, bin_dim=bin_dim)
        else:
            raise ValueError(f"未知模型类型: {self.config.model_type}")
        model_name = self._model_display_name()
        if show_train:
            try:
                from tqdm.auto import tqdm

                tqdm.write(
                    f"[INFO] ② 拟合 {model_name}（特征矩阵 {n_samples:,}×{n_features}，"
                    f"粗估 ~{eta_fit:.0f}s）…",
                    file=sys.stderr,
                )
            except Exception:
                print(
                    f"[INFO] ② 拟合 {model_name}（特征矩阵 {n_samples:,}×{n_features}，"
                    f"粗估 ~{eta_fit:.0f}s）…",
                    flush=True,
                )

        with _model_fit_stderr_progress(
            eta_fit,
            model_name,
            enabled=show_train,
        ):
            self.model.fit(X_train)

        return self

    def _infer_feature_partition(self) -> tuple[int, int]:
        """
        从 features.py 的 ColumnTransformer 中读取连续/二值列数量。
        假设输出顺序与 transformers 列表一致（cont 后 bin）。
        """
        if self.pipeline is None:
            return 0, 0
        pre = self.pipeline.named_steps.get("preprocessor", None)
        if pre is None or not hasattr(pre, "transformers_"):
            return 0, 0
        cont_dim = 0
        bin_dim = 0
        for name, _trans, cols in pre.transformers_:
            if name == "cont":
                cont_dim = int(len(cols))
            elif name == "bin":
                bin_dim = int(len(cols))
        return cont_dim, bin_dim

    def _check_fitted(self):
        if self.pipeline is None or self.model is None:
            raise RuntimeError("模型尚未训练或加载，请先调用 fit() 或 load()。")

    def decision_function(self, df: pd.DataFrame, label_column: str | None = None) -> np.ndarray:
        """
        返回异常分数，值越小越异常。
        """
        self._check_fitted()
        X = transform_features(self.pipeline, df, label_column=label_column)
        return self.model.decision_function(X)

    def predict(self, df: pd.DataFrame, label_column: str | None = None) -> np.ndarray:
        """
        返回预测标签：1 表示正常，-1 表示异常。
        """
        self._check_fitted()
        X = transform_features(self.pipeline, df, label_column=label_column)
        return self.model.predict(X)

    def save(self, path: str) -> None:
        """
        保存模型及特征工程。
        """
        payload = {
            "config": asdict(self.config),
            "pipeline": self.pipeline,
            "model": self.model,
        }
        joblib.dump(payload, path)

    @classmethod
    def load(cls, path: str) -> "WAFUnsupervisedModel":
        payload = joblib.load(path)
        config = ModelConfig(**payload["config"])
        instance = cls(config)
        instance.pipeline = payload["pipeline"]
        instance.model = payload["model"]
        return instance


def train_model(
    df_train: pd.DataFrame,
    config: ModelConfig,
    label_column: str | None = None,
) -> Tuple[WAFUnsupervisedModel, str]:
    """
    训练并保存模型，返回模型实例和保存路径。
    """
    model = WAFUnsupervisedModel(config)
    model.fit(df_train, label_column=label_column)
    path = config.model_path()
    model.save(path)
    return model, path

