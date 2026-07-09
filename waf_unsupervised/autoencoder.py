from __future__ import annotations

import io
from typing import Any, List, Tuple

import numpy as np
import torch

AE_DEVICE_AUTO = "auto"


def _pick_device(explicit: str) -> Any:
    if explicit and explicit.lower() not in ("auto", ""):
        try:
            wanted = torch.device(explicit)
        except Exception:
            wanted = torch.device("cpu")
        if wanted.type == "cuda" and not torch.cuda.is_available():
            return torch.device("cpu")
        return wanted
    if torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")


class _MLPAutoencoder(torch.nn.Module):
    """全连接编码器-解码器，输入为标准化后的特征向量。"""

    def __init__(self, n_features: int, hidden: int, latent: int):
        super().__init__()
        self.encoder = torch.nn.Sequential(
            torch.nn.Linear(n_features, hidden),
            torch.nn.ReLU(),
            torch.nn.Linear(hidden, latent),
            torch.nn.ReLU(),
        )
        self.decoder = torch.nn.Sequential(
            torch.nn.Linear(latent, hidden),
            torch.nn.ReLU(),
            torch.nn.Linear(hidden, n_features),
        )

    def forward(self, x: Any) -> Any:
        z = self.encoder(x)
        return self.decoder(z)


class AutoencoderAnomalyDetector:
    """
    基于重构误差的异常检测：训练集仅含正常流量时最小化 MSE，
    推断时 score = mse_ref - per_sample_mse，与 detect 约定一致（分数越小越异常）。
    """

    def __init__(
        self,
        *,
        hidden_dim: int = 64,
        latent_dim: int = 32,
        epochs: int = 30,
        batch_size: int = 2048,
        lr: float = 1e-3,
        mse_percentile: float = 90.0,
        max_train_samples: int = 0,
        random_state: int = 42,
        decision_threshold: float = 0.05,
        device: str = AE_DEVICE_AUTO,
        loss_alpha: float = 1.0,
        loss_beta: float = 2.0,
        input_dropout: float = 0.10,
        binary_flip_prob: float = 0.15,
    ):
        self.hidden_dim = int(hidden_dim)
        self.latent_dim = int(latent_dim)
        self.epochs = int(epochs)
        self.batch_size = int(batch_size)
        self.lr = float(lr)
        self.mse_percentile = float(mse_percentile)
        self.max_train_samples = int(max_train_samples)
        self.random_state = int(random_state)
        self.decision_threshold = float(decision_threshold)
        self.device_str = device
        self.loss_alpha = float(loss_alpha)
        self.loss_beta = float(loss_beta)
        self.input_dropout = float(input_dropout)
        self.binary_flip_prob = float(binary_flip_prob)

        self._net: Any = None
        self._device: Any = None
        self._input_dim: int = 0
        self._mse_ref: float = 0.0
        self._cont_dim: int = 0
        self._bin_dim: int = 0

    def set_feature_partition(self, cont_dim: int, bin_dim: int) -> "AutoencoderAnomalyDetector":
        self._cont_dim = max(0, int(cont_dim))
        self._bin_dim = max(0, int(bin_dim))
        return self

    def _train_array(self, X: np.ndarray) -> np.ndarray:
        n = len(X)
        if self.max_train_samples > 0 and n > self.max_train_samples:
            rng = np.random.default_rng(self.random_state)
            idx = rng.choice(n, size=self.max_train_samples, replace=False)
            return X[idx]
        return X

    def fit(self, X: np.ndarray, y: Any = None) -> "AutoencoderAnomalyDetector":
        import torch.nn.functional as F

        X = np.asarray(X, dtype=np.float32, order="C")
        if X.ndim != 2:
            raise ValueError(f"Autoencoder 需要二维特征矩阵，得到 shape={X.shape}")

        self._input_dim = int(X.shape[1])
        # 若外部未显式设置分区，默认都按连续特征处理
        if self._cont_dim <= 0 and self._bin_dim <= 0:
            self._cont_dim = self._input_dim
            self._bin_dim = 0
        if self._cont_dim + self._bin_dim > self._input_dim:
            self._cont_dim = self._input_dim
            self._bin_dim = 0

        cont_end = int(self._cont_dim)
        bin_end = int(self._cont_dim + self._bin_dim)
        X_fit = self._train_array(X)
        self._device = _pick_device(self.device_str)
        torch.manual_seed(self._random_torch_seed())

        self._net = _MLPAutoencoder(self._input_dim, self.hidden_dim, self.latent_dim).to(self._device)
        opt = torch.optim.AdamW(self._net.parameters(), lr=self.lr)

        xt = torch.from_numpy(X_fit).to(self._device)
        n_fit = xt.shape[0]
        bs = max(1, min(self.batch_size, n_fit))

        self._net.train()
        for _ep in range(self.epochs):
            perm = torch.randperm(n_fit, device=self._device)
            for start in range(0, n_fit, bs):
                idx = perm[start : start + bs]
                xb = xt[idx]
                # 去噪：输入 dropout + 二值位 0->1 随机翻转，防止网络在稀疏位上“偷懒输出全0”
                xb_in = xb
                if self.input_dropout > 0:
                    keep = (torch.rand_like(xb_in) >= self.input_dropout).to(xb_in.dtype)
                    xb_in = xb_in * keep
                if self.binary_flip_prob > 0 and self._bin_dim > 0:
                    xb_in = xb_in.clone()
                    xb_bin = xb_in[:, cont_end:bin_end]
                    zero_mask = xb_bin <= 0.5
                    flip = (torch.rand_like(xb_bin) < self.binary_flip_prob) & zero_mask
                    xb_bin = torch.where(flip, torch.ones_like(xb_bin), xb_bin)
                    xb_in[:, cont_end:bin_end] = xb_bin

                opt.zero_grad(set_to_none=True)
                recon = self._net(xb_in)
                loss = torch.tensor(0.0, device=self._device)
                if self._cont_dim > 0:
                    recon_cont = recon[:, :cont_end]
                    xb_cont = xb[:, :cont_end]
                    loss = loss + self.loss_alpha * F.mse_loss(recon_cont, xb_cont)
                if self._bin_dim > 0:
                    recon_bin = recon[:, cont_end:bin_end]
                    xb_bin = xb[:, cont_end:bin_end].clamp(0.0, 1.0)
                    loss = loss + self.loss_beta * F.binary_cross_entropy_with_logits(recon_bin, xb_bin)
                loss.backward()
                opt.step()

        self._net.eval()
        with torch.no_grad():
            mse_train = self._reconstruction_mse_torch(X)
        self._mse_ref = float(np.percentile(mse_train, self.mse_percentile))
        return self

    def _random_torch_seed(self) -> int:
        return int(self.random_state) % (2**31)

    def _reconstruction_mse_torch(self, X: np.ndarray) -> np.ndarray:
        """
        兼容历史命名：返回“混合重构误差”（不再仅是 MSE）。
        """
        import torch.nn.functional as F

        X = np.asarray(X, dtype=np.float32, order="C")
        self._net.eval()
        out: List[np.ndarray] = []
        n = X.shape[0]
        bs = max(1, min(self.batch_size, n))
        cont_end = int(self._cont_dim)
        bin_end = int(self._cont_dim + self._bin_dim)
        with torch.no_grad():
            for start in range(0, n, bs):
                xb = torch.from_numpy(X[start : start + bs]).to(self._device)
                recon = self._net(xb)
                err = torch.zeros(xb.shape[0], device=self._device, dtype=xb.dtype)
                if self._cont_dim > 0:
                    mse = torch.mean((recon[:, :cont_end] - xb[:, :cont_end]) ** 2, dim=1)
                    err = err + self.loss_alpha * mse
                if self._bin_dim > 0:
                    bce = F.binary_cross_entropy_with_logits(
                        recon[:, cont_end:bin_end],
                        xb[:, cont_end:bin_end].clamp(0.0, 1.0),
                        reduction="none",
                    ).mean(dim=1)
                    err = err + self.loss_beta * bce
                out.append(err.cpu().numpy())
        return np.concatenate(out, axis=0)

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        mse = self._reconstruction_mse_torch(X)
        return (self._mse_ref - mse).astype(np.float64, copy=False)

    def predict(self, X: np.ndarray) -> np.ndarray:
        s = self.decision_function(X)
        pred = np.ones(s.shape[0], dtype=np.int32)
        pred[s < self.decision_threshold] = -1
        return pred

    def __getstate__(self) -> dict[str, Any]:
        if self._net is None:
            raise RuntimeError("Autoencoder 尚未训练，无法序列化")
        buf = io.BytesIO()
        torch.save(
            {
                "state_dict": self._net.state_dict(),
                "input_dim": self._input_dim,
                "hidden_dim": self.hidden_dim,
                "latent_dim": self.latent_dim,
                "mse_ref": self._mse_ref,
                "decision_threshold": self.decision_threshold,
                "mse_percentile": self.mse_percentile,
                "device_str": self.device_str,
                "loss_alpha": self.loss_alpha,
                "loss_beta": self.loss_beta,
                "input_dropout": self.input_dropout,
                "binary_flip_prob": self.binary_flip_prob,
                "cont_dim": self._cont_dim,
                "bin_dim": self._bin_dim,
            },
            buf,
        )
        return {
            "blob": buf.getvalue(),
            "hparams": {
                "epochs": self.epochs,
                "batch_size": self.batch_size,
                "lr": self.lr,
                "max_train_samples": self.max_train_samples,
                "random_state": self.random_state,
                "loss_alpha": self.loss_alpha,
                "loss_beta": self.loss_beta,
                "input_dropout": self.input_dropout,
                "binary_flip_prob": self.binary_flip_prob,
            },
        }

    def __setstate__(self, state: dict[str, Any]) -> None:
        blob = state["blob"]
        hp = state.get("hparams", {})
        self.epochs = int(hp.get("epochs", 30))
        self.batch_size = int(hp.get("batch_size", 2048))
        self.lr = float(hp.get("lr", 1e-3))
        self.max_train_samples = int(hp.get("max_train_samples", 0))
        self.random_state = int(hp.get("random_state", 42))
        self.loss_alpha = float(hp.get("loss_alpha", 1.0))
        self.loss_beta = float(hp.get("loss_beta", 2.0))
        self.input_dropout = float(hp.get("input_dropout", 0.10))
        self.binary_flip_prob = float(hp.get("binary_flip_prob", 0.05))

        _bio = io.BytesIO(blob)
        try:
            chk = torch.load(_bio, map_location="cpu", weights_only=False)
        except TypeError:
            _bio.seek(0)
            chk = torch.load(_bio, map_location="cpu")
        self._input_dim = int(chk["input_dim"])
        self.hidden_dim = int(chk["hidden_dim"])
        self.latent_dim = int(chk["latent_dim"])
        self._mse_ref = float(chk["mse_ref"])
        self.decision_threshold = float(chk["decision_threshold"])
        self.mse_percentile = float(chk.get("mse_percentile", 90.0))
        self.device_str = str(chk.get("device_str", AE_DEVICE_AUTO))
        self.loss_alpha = float(chk.get("loss_alpha", self.loss_alpha))
        self.loss_beta = float(chk.get("loss_beta", self.loss_beta))
        self.input_dropout = float(chk.get("input_dropout", self.input_dropout))
        self.binary_flip_prob = float(chk.get("binary_flip_prob", self.binary_flip_prob))
        self._cont_dim = int(chk.get("cont_dim", self._input_dim))
        self._bin_dim = int(chk.get("bin_dim", 0))

        self._device = _pick_device(self.device_str)
        self._net = _MLPAutoencoder(self._input_dim, self.hidden_dim, self.latent_dim).to(self._device)
        self._net.load_state_dict(chk["state_dict"])
        self._net.eval()
