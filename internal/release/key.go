package release

// releaseKey is the public half of the key itter's releases are signed with
// (pqc.ReleaseKeyBytes, base64). Its fingerprint is in the README, and
// `itter version` shows the fingerprint of the one in the program at hand.
// Builds made by hand leave it empty: they cannot check updates.
var releaseKey = "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" +
	"sumjEkmoazqO"

// ReleaseKeyFingerprint is the fingerprint of releaseKey, as people compare it.
const ReleaseKeyFingerprint = "6272 705b 6200 d258 80dd 12c9 7db1 911b"
