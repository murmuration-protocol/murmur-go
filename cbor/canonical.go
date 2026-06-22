package cbor

import "math/big"

// CheckDecimal reports whether a [scale, mantissa] pair is a canonical decimal,
// returning a descriptive error if not. The wire shape is shared with the
// rational and with a plain integer array, so this is a meaning-level check the
// byte decoder cannot make: it applies only once a schema declares the field a
// decimal. The rules are: zero is the single form [0, 0], and otherwise the
// mantissa MUST NOT be divisible by ten (trailing zeros are stripped). The sign
// rides on the mantissa, which a big.Int carries inherently; minimal integer
// encoding is the byte decoder's job.
func CheckDecimal(scale, mantissa *big.Int) error {
	if scale == nil || mantissa == nil {
		return &EncodeError{Msg: "decimal has a nil component"}
	}
	if mantissa.Sign() == 0 {
		if scale.Sign() != 0 {
			return &EncodeError{Msg: "canonical zero decimal is [0, 0]"}
		}
		return nil
	}
	if new(big.Int).Mod(mantissa, bigTen).Sign() == 0 {
		return &EncodeError{Msg: "decimal mantissa must not be divisible by ten"}
	}
	return nil
}

// CheckRational reports whether a [numerator, denominator] pair is a canonical
// rational, returning a descriptive error if not. Like CheckDecimal this is a
// meaning-level check, applied once a schema declares the field a rational. The
// rules are: the denominator MUST be positive and non-zero, the numerator and
// denominator MUST be coprime, and zero is the single form [0, 1].
func CheckRational(num, den *big.Int) error {
	if num == nil || den == nil {
		return &EncodeError{Msg: "rational has a nil component"}
	}
	if den.Sign() <= 0 {
		return &EncodeError{Msg: "rational denominator must be positive"}
	}
	if num.Sign() == 0 {
		if den.Cmp(bigOne) != 0 {
			return &EncodeError{Msg: "canonical zero rational is [0, 1]"}
		}
		return nil
	}
	if new(big.Int).GCD(nil, nil, new(big.Int).Abs(num), den).Cmp(bigOne) != 0 {
		return &EncodeError{Msg: "rational numerator and denominator must be coprime"}
	}
	return nil
}
