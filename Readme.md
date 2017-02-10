# CryptAnalyze

A Static Analysis tool, based on [Soot](https://sable.github.io/soot/), for specifically analyzing Android APKs, to identify certain cryptographic rules.

The safety properties that it looks for are the following:
* Modes should not be ECB (at least not for multiple blocks being encrypted)
* Static Initialization Vectors (IVs) shouldn’t be used
* Constant encryption keys shouldn’t be used
* Constant salts shouldn’t be used
* Password Based Encryption should make use of at least 1000 iterations
* Secure Random shouldn’t be statically seeded

The tool outputs a text file, under a "Logs" directory, that it generates during the course of execution. The text file enlists the violations, if any.

## References:
* [Soot](https://github.com/Sable/soot)
* [Soot-infoflow](https://github.com/secure-software-engineering/soot-infoflow)
* [Soot-infoflow-android](https://github.com/secure-software-engineering/soot-infoflow-android)