import os
from dataclasses import dataclass
from typing import Literal, Union


ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT_DIR, "data")
MODEL_DIR = os.path.join(ROOT_DIR, "models")
os.makedirs(MODEL_DIR, exist_ok=True)


@dataclass
class DataConfig:
    # 默认文件名，可以根据需要在命令行参数覆盖
    train_filename: str = "train.json"
    detect_filename: str = "detection_1.json"
    label_column: str = "label"  # 检测数据中的标签列（0 正常，1 异常），如无可留空并在 detect 中关闭评估

    @property
    def train_path(self) -> str:
        return os.path.join(DATA_DIR, self.train_filename)

    @property
    def detect_path(self) -> str:
        return os.path.join(DATA_DIR, self.detect_filename)


ModelType = Literal["isolation_forest", "one_class_svm", "autoencoder"]
OcsvmBackend = Literal["sklearn", "thundersvm"]


@dataclass
class ModelConfig:
    model_type: ModelType = "one_class_svm"  # 改用 One-Class SVM
    contamination: float = "auto"  # 无监督时设为 auto，让模型自动估计
    random_state: int = 42

    # One-Class SVM 特有参数
    ocsvm_kernel: str = "rbf"
    ocsvm_nu: float = 0.12  # 保持较小值，因为训练集全是正常样本
    ocsvm_gamma: Union[str, float] = "scale"
    # sklearn / ThunderSVM(GPU)；需 pip 安装与本机 CUDA 匹配的 thundersvm
    ocsvm_backend: OcsvmBackend = "sklearn"
    thundersvm_gpu_id: int = 0

    # 深度自编码器（PyTorch MLP AE，重构误差异常检测）
    ae_hidden_dim: int = 64
    ae_latent_dim: int = 32
    ae_epochs: int = 30
    ae_batch_size: int = 2048
    ae_lr: float = 1e-3
    ae_mse_percentile: float = 90.0
    ae_max_train_samples: int = 0  # 0 表示使用全部训练样本
    ae_device: str = "auto"  # auto / cuda / cpu / cuda:0 等
    # AAE/AE 混合重构损失：L = alpha*MSE(cont) + beta*BCE(bin)
    ae_loss_alpha: float = 1.0
    ae_loss_beta: float = 2.0
    # 稀疏二值特征去噪策略
    ae_input_dropout: float = 0.10
    ae_binary_flip_prob: float = 0.05

    # 决策阈值（新增）- 这是调优的关键
    decision_threshold: float = 0.05  # 默认0，负数提高检出率
    
    def model_path(self) -> str:
        name = f"{self.model_type}.joblib"
        return os.path.join(MODEL_DIR, name)
        
data_config = DataConfig()
model_config = ModelConfig()

