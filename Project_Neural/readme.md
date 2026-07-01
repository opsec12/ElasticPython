# Neural Network

Built a fully-connected feedforward neural network using only NumPy no PyTorch, no TensorFlow. The goal was to actually understand what's happening under the hood rather than just calling `.fit()` on a black box.

## What's implemented

- Forward pass with configurable layer depths
- Backpropagation with analytically derived gradients
- Mini-batch SGD with optional learning rate decay
- ReLU, Sigmoid, Tanh, and Softmax activations
- He and Xavier weight initialization
- Inverted dropout regularization
- L2 weight penalty
- Binary cross-entropy and categorical cross-entropy loss
- Training history plots and decision boundary visualization

## Setup

**Linux / Mac**
```bash
pip install numpy matplotlib scikit-learn
```

**Windows (Anaconda)**
```bash
conda install conda-forge::matplotlib
```

## Run it

```bash
python neural.py
```

Runs two demos back to back — binary classification on the classic moons dataset, then a 4-class problem with 10 input features. Saves training curves to `nn_training_history.png` and the decision boundary to `decision_boundary.png`.

## Example config

```python
model = NeuralNetwork(
    layer_dims   = [2, 64, 32, 16, 1],
    activations  = ["relu", "relu", "relu", "sigmoid"],
    learning_rate = 0.05,
    lr_decay     = 0.995,
    lambda_reg   = 1e-4,
    dropout_rate = 0.1,
)
model.fit(X_train, y_train, X_val, y_val, epochs=200, batch_size=64)
```

`layer_dims` controls the architecture — first value is input features, last is output size. One activation per layer after the input.

## Notes

Dropout uses the inverted scaling trick so you don't have to adjust anything at inference time. Gradients for the output layer are collapsed with the loss derivative, which is the standard approach for sigmoid+BCE and softmax+CCE — saves a multiplication and avoids numerical issues.
