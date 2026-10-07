package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MaxLength       = 128
	saltLength      = 16
	argonMemory     = 19 * 1024
	argonIterations = 2
	argonLanes      = 1
	argonKeySize    = 32
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
	}

	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	derivedKey := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonLanes, argonKeySize)

	return encodeArgon2idHash(argon2idHash{
		version:     argon2.Version,
		memoryKiB:   argonMemory,
		iterations:  argonIterations,
		parallelism: argonLanes,
		salt:        salt,
		derivedKey:  derivedKey,
	}), nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}

	if legacyHash, ok := decodeLegacyHash(encodedHash); ok {
		candidateHash := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(candidateHash[:], legacyHash) == 1
	}

	argonHash, valid := parseArgon2idHash(encodedHash)
	if !valid || argonHash.version != argon2.Version {
		return false
	}
	derivedCandidate := argon2.IDKey(
		[]byte(password),
		argonHash.salt,
		argonHash.iterations,
		argonHash.memoryKiB,
		argonHash.parallelism,
		uint32(len(argonHash.derivedKey)),
	)

	return subtle.ConstantTimeCompare(argonHash.derivedKey, derivedCandidate) == 1
}

func NeedsRehash(encodedHash string) bool {
	// legacy SHA-256 hashses are exactly 64 hex characters long
	if _, ok := decodeLegacyHash(encodedHash); ok {
		return true
	}
	argonHash, valid := parseArgon2idHash(encodedHash)
	if valid {
		if argonHash.version != argon2.Version || argonHash.iterations != argonIterations || argonHash.memoryKiB != argonMemory || argonHash.parallelism != argonLanes || len(argonHash.derivedKey) != argonKeySize {
			return true
		}
	}
	return false
}
