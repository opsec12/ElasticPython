"""
Neural Network
============================
A fully-connected feedforward neural network implemented using only NumPy. Demonstrates: forward pass, backpropagation, mini-batch SGD, multiple activation functions.

Usage:
    python neural.py

Requirements:
    For linux-> pip install numpy matplotlib scikit-learn
    For Anaconda -> conda install conda-forge::matplotlib
"""

import numpy as np
import matplotlib.pyplot as plt
from sklearn.datasets import make_moons, make_classification
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from typing import List, Tuple, Dict, Callable


# Activation functions & their derivatives


def relu(z: np.ndarray) -> np.ndarray:
    return np.maximum(0, z)

def relu_grad(z: np.ndarray) -> np.ndarray:
    return (z > 0).astype(float)

def sigmoid(z: np.ndarray) -> np.ndarray:
    return 1 / (1 + np.exp(-np.clip(z, -500, 500)))

def sigmoid_grad(z: np.ndarray) -> np.ndarray:
    s = sigmoid(z)
    return s * (1 - s)

def tanh_act(z: np.ndarray) -> np.ndarray:
    return np.tanh(z)

def tanh_grad(z: np.ndarray) -> np.ndarray:
    return 1 - np.tanh(z) ** 2

def softmax(z: np.ndarray) -> np.ndarray:
    e = np.exp(z - z.max(axis=1, keepdims=True))
    return e / e.sum(axis=1, keepdims=True)

ACTIVATIONS: Dict[str, Tuple[Callable, Callable]] = {
    "relu":    (relu,     relu_grad),
    "sigmoid": (sigmoid,  sigmoid_grad),
    "tanh":    (tanh_act, tanh_grad),
}


# Weight initialization


def init_weights(layer_dims: List[int], method: str = "he") -> List[Dict]:
    """
    Initialize weights for each layer.

    Args:
        layer_dims: List of neuron counts per layer including input.
        method: 'he' for ReLU layers, 'xavier' for tanh/sigmoid.

    Returns:
        List of {'W': ..., 'b': ...} dicts.
    """
    params = []
    for i in range(1, len(layer_dims)):
        fan_in = layer_dims[i - 1]
        fan_out = layer_dims[i]

        if method == "he":
            scale = np.sqrt(2.0 / fan_in)
        elif method == "xavier":
            scale = np.sqrt(2.0 / (fan_in + fan_out))
        else:
            scale = 0.01

        params.append({
            "W": np.random.randn(fan_in, fan_out) * scale,
            "b": np.zeros((1, fan_out)),
        })
    return params


# Core neural network class


class NeuralNetwork:
    """
    Flexible feedforward neural network.

    Args:
        layer_dims:  List of ints — [input_dim, hidden1, ..., output_dim].
        activations: List of activation names per hidden+output layer.
        learning_rate: Initial LR for SGD.
        lr_decay:    Multiply LR by this factor each epoch.
        lambda_reg:  L2 regularization strength.
        dropout_rate: Fraction of neurons to drop during training (0 = off).
    """

    def __init__(
        self,
        layer_dims: List[int],
        activations: List[str],
        learning_rate: float = 0.01,
        lr_decay: float = 1.0,
        lambda_reg: float = 0.0,
        dropout_rate: float = 0.0,
    ):
        assert len(activations) == len(layer_dims) - 1, (
            "Need one activation per layer (excluding input)."
        )
        self.layer_dims   = layer_dims
        self.activations  = activations
        self.lr           = learning_rate
        self.lr_decay     = lr_decay
        self.lambda_reg   = lambda_reg
        self.dropout_rate = dropout_rate
        self.params       = init_weights(layer_dims, method="he")
        self.history: Dict[str, List[float]] = {"train_loss": [], "val_loss": [], "val_acc": []}

    # Forward pass

    def _forward(self, X: np.ndarray, training: bool = True) -> Tuple[np.ndarray, List[Dict]]:
        """
        Run a full forward pass through the network.

        Returns:
            output: Final layer activations (predictions).
            cache:  Per-layer cache needed for backprop.
        """
        cache = []
        A = X

        for i, (layer, act_name) in enumerate(zip(self.params, self.activations)):
            Z = A @ layer["W"] + layer["b"]
            act_fn, _ = ACTIVATIONS[act_name]
            A_new = act_fn(Z)

            # Inverted dropout (skip on last layer and during inference)
            mask = None
            if training and self.dropout_rate > 0 and i < len(self.params) - 1:
                mask = (np.random.rand(*A_new.shape) > self.dropout_rate).astype(float)
                A_new = (A_new * mask) / (1 - self.dropout_rate)

            cache.append({"A_prev": A, "Z": Z, "mask": mask, "act": act_name})
            A = A_new

        return A, cache

    # Loss functions

    def _compute_loss(self, Y_pred: np.ndarray, Y_true: np.ndarray) -> float:
        m = Y_true.shape[0]
        # Binary cross-entropy for sigmoid output; CCE for softmax
        if self.activations[-1] == "sigmoid":
            loss = -np.mean(
                Y_true * np.log(Y_pred + 1e-9) + (1 - Y_true) * np.log(1 - Y_pred + 1e-9)
            )
        else:
            loss = -np.mean(np.sum(Y_true * np.log(Y_pred + 1e-9), axis=1))

        # L2 regularization term
        l2 = sum(np.sum(p["W"] ** 2) for p in self.params)
        loss += (self.lambda_reg / (2 * m)) * l2
        return float(loss)

    # Backward pass

    def _backward(self, Y_pred: np.ndarray, Y_true: np.ndarray, cache: List[Dict]) -> List[Dict]:
        """Backpropagation — compute gradients for all layers."""
        m = Y_true.shape[0]
        grads = [None] * len(self.params)

        # Output layer gradient (dL/dZ collapsed for softmax/sigmoid + CE)
        dA = Y_pred - Y_true  # works for both sigmoid+BCE and softmax+CCE

        for i in reversed(range(len(self.params))):
            c = cache[i]
            _, act_grad = ACTIVATIONS[c["act"]]

            if i == len(self.params) - 1:
                dZ = dA  # gradient already collapsed above
            else:
                dZ = dA * act_grad(c["Z"])

            # Dropout mask (re-apply during backward)
            if c["mask"] is not None:
                dZ = (dZ * c["mask"]) / (1 - self.dropout_rate)

            dW = (c["A_prev"].T @ dZ) / m + (self.lambda_reg / m) * self.params[i]["W"]
            db = dZ.mean(axis=0, keepdims=True)
            dA = dZ @ self.params[i]["W"].T

            grads[i] = {"dW": dW, "db": db}

        return grads

    # Parameter update (SGD with momentum)

    def _update(self, grads: List[Dict]) -> None:
        for i, (p, g) in enumerate(zip(self.params, grads)):
            p["W"] -= self.lr * g["dW"]
            p["b"] -= self.lr * g["db"]

    # Public API

    def fit(
        self,
        X_train: np.ndarray,
        Y_train: np.ndarray,
        X_val: np.ndarray = None,
        Y_val: np.ndarray = None,
        epochs: int = 200,
        batch_size: int = 64,
        verbose: bool = True,
    ) -> "NeuralNetwork":
        """Train the network using mini-batch SGD."""
        m = X_train.shape[0]

        for epoch in range(1, epochs + 1):
            # Shuffle
            idx = np.random.permutation(m)
            X_shuf, Y_shuf = X_train[idx], Y_train[idx]

            # Mini-batches
            for start in range(0, m, batch_size):
                Xb = X_shuf[start:start + batch_size]
                Yb = Y_shuf[start:start + batch_size]
                Y_pred, cache = self._forward(Xb, training=True)
                grads = self._backward(Y_pred, Yb, cache)
                self._update(grads)

            # LR decay
            self.lr *= self.lr_decay

            # Logging
            train_pred, _ = self._forward(X_train, training=False)
            train_loss = self._compute_loss(train_pred, Y_train)
            self.history["train_loss"].append(train_loss)

            if X_val is not None:
                val_pred, _ = self._forward(X_val, training=False)
                val_loss = self._compute_loss(val_pred, Y_val)
                val_acc  = self._accuracy(val_pred, Y_val)
                self.history["val_loss"].append(val_loss)
                self.history["val_acc"].append(val_acc)

                if verbose and epoch % 20 == 0:
                    print(f"Epoch {epoch:4d} | train_loss={train_loss:.4f} | "
                          f"val_loss={val_loss:.4f} | val_acc={val_acc:.4f}")
            elif verbose and epoch % 20 == 0:
                print(f"Epoch {epoch:4d} | train_loss={train_loss:.4f}")

        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        out, _ = self._forward(X, training=False)
        return out

    def predict(self, X: np.ndarray) -> np.ndarray:
        proba = self.predict_proba(X)
        if proba.shape[1] == 1:
            return (proba >= 0.5).astype(int)
        return proba.argmax(axis=1)

    def _accuracy(self, Y_pred: np.ndarray, Y_true: np.ndarray) -> float:
        if Y_pred.shape[1] == 1:
            preds = (Y_pred >= 0.5).astype(int)
            return float((preds == Y_true).mean())
        return float((Y_pred.argmax(axis=1) == Y_true.argmax(axis=1)).mean())

    def plot_history(self) -> None:
        fig, axes = plt.subplots(1, 2, figsize=(12, 4))
        axes[0].plot(self.history["train_loss"], label="Train Loss")
        if self.history["val_loss"]:
            axes[0].plot(self.history["val_loss"], label="Val Loss")
        axes[0].set_title("Loss")
        axes[0].set_xlabel("Epoch")
        axes[0].legend()

        if self.history["val_acc"]:
            axes[1].plot(self.history["val_acc"], color="green", label="Val Accuracy")
            axes[1].set_title("Validation Accuracy")
            axes[1].set_xlabel("Epoch")
            axes[1].legend()

        plt.tight_layout()
        plt.savefig("nn_training_history.png", dpi=150)
        print("Training history saved to nn_training_history.png")
        plt.show()

    def plot_decision_boundary(self, X: np.ndarray, Y: np.ndarray) -> None:
        """Only works for 2-feature input."""
        h = 0.02
        x_min, x_max = X[:, 0].min() - 0.5, X[:, 0].max() + 0.5
        y_min, y_max = X[:, 1].min() - 0.5, X[:, 1].max() + 0.5
        xx, yy = np.meshgrid(np.arange(x_min, x_max, h),
                              np.arange(y_min, y_max, h))
        grid = np.c_[xx.ravel(), yy.ravel()]
        Z = self.predict(grid).reshape(xx.shape)

        plt.figure(figsize=(8, 6))
        plt.contourf(xx, yy, Z, alpha=0.4, cmap="RdYlBu")
        plt.scatter(X[:, 0], X[:, 1], c=Y.ravel(), cmap="RdYlBu", edgecolors="k", s=30)
        plt.title("Decision Boundary")
        plt.savefig("decision_boundary.png", dpi=150)
        print("Decision boundary saved to decision_boundary.png")
        plt.show()


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def demo_binary_classification() -> None:
    print("=" * 60)
    print("Demo: Binary Classification on make_moons")
    print("=" * 60)

    X, y = make_moons(n_samples=1000, noise=0.25, random_state=42)
    X = StandardScaler().fit_transform(X)
    y = y.reshape(-1, 1).astype(float)

    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

    model = NeuralNetwork(
        layer_dims  = [2, 64, 32, 16, 1],
        activations = ["relu", "relu", "relu", "sigmoid"],
        learning_rate = 0.05,
        lr_decay    = 0.995,
        lambda_reg  = 1e-4,
        dropout_rate = 0.1,
    )
    model.fit(X_train, y_train, X_val, y_val, epochs=200, batch_size=64)

    final_acc = model._accuracy(model.predict_proba(X_val), y_val)
    print(f"\nFinal validation accuracy: {final_acc:.4f}")

    model.plot_history()
    model.plot_decision_boundary(X, y)


def demo_multiclass() -> None:
    print("=" * 60)
    print("Demo: Multiclass Classification")
    print("=" * 60)

    X, y = make_classification(
        n_samples=1200, n_features=10, n_classes=4,
        n_informative=6, random_state=42
    )
    X = StandardScaler().fit_transform(X)

    # One-hot encode
    num_classes = 4
    Y = np.eye(num_classes)[y]

    X_train, X_val, Y_train, Y_val = train_test_split(X, Y, test_size=0.2, random_state=42)

    model = NeuralNetwork(
        layer_dims  = [10, 128, 64, 4],
        activations = ["relu", "relu", "softmax"],
        learning_rate = 0.01,
        lr_decay    = 0.998,
        lambda_reg  = 1e-4,
    )
    model.fit(X_train, Y_train, X_val, Y_val, epochs=300, batch_size=64)

    final_acc = model._accuracy(model.predict_proba(X_val), Y_val)
    print(f"\nFinal validation accuracy: {final_acc:.4f}")
    model.plot_history()


if __name__ == "__main__":
    np.random.seed(42)
    demo_binary_classification()
    demo_multiclass()
