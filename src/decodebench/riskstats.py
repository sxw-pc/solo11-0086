"""组级二项风险的单侧精确上界（Clopper-Pearson，仅依赖标准库）。

自动交付的风险单位是“来源组”而非组内变体：同一原始网页的多个编码/声明
变体共享同一错误机制，不能当作独立样本。因此有效样本数 n 为被覆盖的来源
组数，错误数 x 为其中交付错误（错误文本或不确定标签，视合同而定）的组数。

单侧 95% 精确上界即 Beta(x, n-x+1) 的 0.95 分位数；x=0 时退化为
1 - 0.05**(1/n)（“三倍律”的精确版本）。零错误绝不等于零风险：n 很小时
该上界仍然很高，门槛必须因此拒判。
"""

from __future__ import annotations

import math

_EPS = 1e-15


def _betacf(a: float, b: float, x: float) -> float:
    """连分式展开（Lentz 算法），用于正则化不完全 Beta 函数。"""
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < _EPS:
        d = _EPS
    d = 1.0 / d
    h = d
    for m in range(1, 401):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < _EPS:
            d = _EPS
        c = 1.0 + aa / c
        if abs(c) < _EPS:
            c = _EPS
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < _EPS:
            d = _EPS
        c = 1.0 + aa / c
        if abs(c) < _EPS:
            c = _EPS
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 3e-14:
            break
    return h


def betainc(a: float, b: float, x: float) -> float:
    """正则化不完全 Beta 函数 I_x(a, b)。"""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    log_bt = (
        math.lgamma(a + b)
        - math.lgamma(a)
        - math.lgamma(b)
        + a * math.log(x)
        + b * math.log1p(-x)
    )
    if x < (a + 1.0) / (a + b + 2.0):
        return math.exp(log_bt) * _betacf(a, b, x) / a
    return 1.0 - math.exp(log_bt) * _betacf(b, a, 1.0 - x) / b


def _beta_quantile(p: float, a: float, b: float) -> float:
    """二分法求 Beta(a,b) 的 p 分位数，结果完全确定。"""
    low, high = 0.0, 1.0
    for _ in range(80):
        mid = (low + high) / 2.0
        if betainc(a, b, mid) < p:
            low = mid
        else:
            high = mid
    return (low + high) / 2.0


def clopper_pearson_upper(errors: int, trials: int, confidence: float = 0.95) -> float:
    """单侧精确上界 P(error_rate <= bound) >= confidence。

    trials 为 0 时没有任何证据，上界取 1.0（必须拒判）。
    """
    if trials <= 0:
        return 1.0
    if not 0 <= errors <= trials:
        raise ValueError("errors 必须满足 0 <= errors <= trials")
    if not 0.5 < confidence < 1.0:
        raise ValueError("confidence 必须落在 (0.5, 1.0)")
    if errors == 0:
        return 1.0 - (1.0 - confidence) ** (1.0 / trials)
    if errors == trials:
        return 1.0
    return _beta_quantile(confidence, float(errors), float(trials - errors) + 1.0)
