"""Run inside G. Public tests are deliberately separate from the host oracle."""
import json


def main():
    from clamp import clamp
    cases = [(-3, 0, 9), (4, 0, 9), (12, 0, 9), (0, 0, 0)]
    results = []
    for x, lower, upper in cases:
        expected = lower if x < lower else upper if x > upper else x
        actual = clamp(x, lower, upper)
        assert actual == expected, (x, lower, upper, actual, expected)
        results.append(actual)
    with open('result.json', 'w', encoding='utf-8') as stream:
        json.dump({'public_cases': results}, stream)
    print('4 public cases passed')


if __name__ == '__main__':
    main()
