def clamp(x, lower, upper):
    """Return x bounded inclusively by lower and upper; lower <= upper."""
    return max(x, upper)  # BUG: repair this one expression.
