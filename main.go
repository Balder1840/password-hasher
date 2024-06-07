// https://github.com/dotnet/aspnetcore/blob/main/src/Identity/Extensions.Core/src/PasswordHasher.cs

package main

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

/* =======================
 * HASHED PASSWORD FORMATS
 * =======================
 *
 * Version 3:
 * PBKDF2 with HMAC-SHA512, 128-bit salt, 256-bit subkey, 100000 iterations.
 * Format: { 0x01, prf (UInt32), iter count (UInt32), salt length (UInt32), salt, subkey }
 * (All UInt32s are stored big-endian.)
 */

var DefaultParams = &Params{
	Iterations: 100000,
	SaltLength: 128 / 8,
	KeyLength:  256 / 8,
}

type Params struct {
	// The number of iterations.
	Iterations uint32
	// Length of the random salt. 16 bytes is recommended for password hashing.
	SaltLength uint32
	// Length of the generated key. 16 bytes or more is recommended.
	KeyLength uint32
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("please input the password you want to hash:")
		return
	}

	passwordStr := os.Args[1]

	hashedPassword, err := createHash(passwordStr, DefaultParams)
	if err != nil {
		fmt.Println("failed to compute hash for the password")
		return
	}

	fmt.Println(hashedPassword)
}

func createHash(password string, params *Params) (hash string, err error) {
	salt, err := generateRandomBytes(params.SaltLength)
	if err != nil {
		return "", err
	}

	subKey := pbkdf2.Key([]byte(password), salt, int(params.Iterations), int(params.KeyLength), sha512.New)

	startForSalt := 13
	saltLen := len(salt)
	offset := saltLen + startForSalt

	outputBytes := make([]byte, 13+saltLen+len(subKey))
	outputBytes[0] = 0x01
	writeNetworkByteOrder(outputBytes, 1, uint(2))
	writeNetworkByteOrder(outputBytes, 5, uint(params.Iterations))
	writeNetworkByteOrder(outputBytes, 9, uint(params.SaltLength))
	copy(outputBytes[startForSalt:offset], salt)
	copy(outputBytes[offset:], subKey)

	hash = base64.StdEncoding.EncodeToString(outputBytes)
	return hash, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func writeNetworkByteOrder(buffer []byte, offset int, value uint) {
	buffer[offset+0] = (byte)(value >> 24)
	buffer[offset+1] = (byte)(value >> 16)
	buffer[offset+2] = (byte)(value >> 8)
	buffer[offset+3] = (byte)(value >> 0)
}
