package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json"
	"encoding/base64"
	"fmt"
	"math/big"
)

type proof struct {
	QaPrime			*ecdsa.PublicKey	`json:"QaPrime"`
	CompressedR		[]byte				`json:"CompressedRx, omitempty"`
	Proof			*ecdsaSignature		`json:"Proof"`
}

type ecdsaSignature struct {
	R, S *big.Int
}

type ecdsaPoint struct {
	X, Y *big.Int
}

var (
	curve = elliptic.P256()
	tokenPayload1 = "First message to be signed"
	tokenPayload2 = "Second message to be included in ZKP"
)


func main() {

	// Choose signature scheme
	compressedMode := true

	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		fmt.Printf("Error generating ECDSA key pair: %s\n", err)
		return
	}

	var r, s *big.Int
	if compressedMode == true {
		// ECDSA signature with compressed R point
		fmt.Printf("Generate ECDSA signature:\n")
		r, s, err = ecdsaSign(privateKey, []byte(tokenPayload1))
		if err != nil {
			fmt.Printf("Error signing token payload: %s\n", err)
			return
		}
	} else {
		// Sign the token payload with standard ECDSA scheme (not-compressed R)
		hash := Hash(tokenPayload1)
		r, s, err = ecdsa.Sign(rand.Reader, privateKey,  hash.Bytes())
		if err != nil {
			fmt.Printf("Error signing token payload: %s\n", err)
			return
		}
	}	
	fmt.Printf("-------------------\n\n")

	// Encode the ECDSA signature
	signatureBytes, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		fmt.Printf("Error encoding ECDSA signature: %s\n", err)
		return
	}

	// Generate zero-knowledge proof
	fmt.Printf("Generate ZKP of ECDSA signature:\n")
	zkProof, err := GenerateZKP(privateKey, signatureBytes, [][]byte{[]byte(tokenPayload1),[]byte(tokenPayload2)}, compressedMode)
	if err != nil {
		fmt.Printf("Error generating zero-knowledge proof: %s\n", err)
		return
	}
	fmt.Printf("-------------------\n\n")

	// Verify zero-knowledge proof
	fmt.Printf("Verify ZKP of ECDSA signature:\n")
	publicKey := privateKey.Public()
	if !VerifyZKP(zkProof,publicKey.(*ecdsa.PublicKey), [][]byte{[]byte(tokenPayload1),[]byte(tokenPayload2)}) {
		fmt.Printf("ZKP not valid!!\n")
		return
	}
	fmt.Printf("ZKP successfully validated!\n")
	fmt.Printf("-------------------\n\n")

	// Encode the zero-knowledge proof to JSON
	zkProofJSON, err := json.Marshal(zkProof)
	if err != nil {
		fmt.Printf("Error encoding zero-knowledge proof to JSON: %s\n", err)
		return
	}

	// Encode the zero-knowledge proof JSON to base64
	zkProofBase64 := base64.StdEncoding.EncodeToString(zkProofJSON)
	fmt.Printf("Encoded proof (Base64): %s\n", zkProofBase64)
	fmt.Printf("-------------------\n\n")
}

func GenerateZKP(privateKey *ecdsa.PrivateKey, signature []byte, message [][]byte, compressed bool) (zkProof *proof, err error) {

	fmt.Println("Message to be included in ZKP: ", string(message[1]))

	// 1 - Retrieve y-coord from R point to Calculate Qa' = signature.s * R
	// 1.1 - Extract r and s from the original ECDSA signature
	asn1Sig := new(ecdsaSignature)
	_, err = asn1.Unmarshal(signature, asn1Sig)
	if err != nil {
		return nil, fmt.Errorf("error parsing ASN.1 signature: %s", err)
	}

	// 2 - Compute hashes 
	// TODO: Inlcude Pubkeys e.g.: h' = HASH(Qa' || message to be included in ZKP)
	m			:= Hash(string(message[0]))
	newMessage	:= Hash(string(message[1]))

	var RPoint *ecdsaPoint
	if compressed == true {
		// 2.1 - Recover the y-coordinate from the signature.r (x-coordinate)
		coordX, coordY, err := uncompressPoint(curve, asn1Sig.R.Bytes())
		if err != nil {
			return nil, fmt.Errorf("error recovering y-coordinate from R: %s", err)
		}
	
		// 2.2 - Create a valid point on the curve
		RPoint = &ecdsaPoint{
			X:     coordX,
			Y:     coordY,
		}
	} else {
		// 2.1 - Recover the 2 y-coordinates from the signature.r (x-coordinate)
		y1, y2, err := getYCoordinates(asn1Sig.R)
		if err != nil {
			return nil, fmt.Errorf("error recovering y-coordinate from R: %s", err)
		}

		// 2.2 - Validate y coordinates through checking Qa' = (m * G) + (r * Qa)
		correctY := checkYCoordinates(y1, y2, asn1Sig.R, asn1Sig.S, m, privateKey.Public().(*ecdsa.PublicKey))
		if correctY == nil {
			return nil, fmt.Errorf("No valid y-coordinate values recovered: %s", err)
		}
		// 2.3 - Verify if point is on curve
		if !curve.IsOnCurve(asn1Sig.R, correctY) {
			return nil, fmt.Errorf("Point is not on Curve!!\n")
		}
		fmt.Println("VALID COORDINATE FOUND!")

		// 2.4 - Create a valid point on the curve
		RPoint = &ecdsaPoint{
			X:     asn1Sig.R,
			Y:     correctY,
		}	
	}

	// Using R point, 
	// 1.4 Compute Qa' = R * signature.s
	// Here, R act as Generator
	QaPrimeX, QaPrimeY := curve.ScalarMult(RPoint.X, RPoint.Y, asn1Sig.S.Bytes())
	
	// 3 Generate new nonce k'
	kPrime, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		return nil, fmt.Errorf("error generating new nonce: %s", err)
	}

	// 3.1 Compute R' such that R' = k' * R
	RPrimeX, RPrimeY := curve.ScalarMult(RPoint.X, RPoint.Y, kPrime.Bytes())

	// Compress RPrime point
	compressedRPrime, err := compressPoint(curve, RPrimeX, RPrimeY)
	if err != nil {
		fmt.Println("Error compressing point:", err)
	}

	/////// Debug and TEST
		// // (R' * m') / k' = m' * R

		// // (R' * m')
		// NewX, NewY := curve.ScalarMult(RPrimeX, RPrimeY, m.Bytes())
		// // fmt.Println("R * message: ", NewX, NewY)

		// // k'^-1
		// invK := new(big.Int).ModInverse(kPrime, curve.Params().N)

		// // (R' * m') / k'
		// LeftX, LeftY := curve.ScalarMult(NewX, NewY, invK.Bytes())

		// // m' * R
		// rightX, rightY := curve.ScalarMult(RPoint.X, RPoint.Y, m.Bytes())

		// // Check if left == right
		// fmt.Println(`GenerateZKP Validation performs: (R' * m') / k' = m' * R`)
		// if (LeftX.Cmp(rightX) == 0) && (LeftY.Cmp(rightY) == 0) {
		// 	fmt.Println(`Validation successfull!`)
		// } else {
		// 	fmt.Println(`Validation Failed!`)
		// }

	////////

	// Compute s' = k'^{-1}(m + signature.S * r')
	// k'^{-1}
	invK := new(big.Int).ModInverse(kPrime, curve.Params().N)
	// (signature.S * r')
	s := new(big.Int).Mul(asn1Sig.S, RPrimeX)
	// (m + signature.S * r')
	s.Add(s, newMessage)
	// k'^{-1}(m + signature.S * r')
	s.Mul(s, invK)
	s.Mod(s, curve.Params().N)

	// Compress original R point to ease the retrieval of its coordinates in validation
	compressedR, err := compressPoint(curve, RPoint.X, RPoint.Y)
	if err != nil {
		return nil, fmt.Errorf("error compressing R: %s\n", err)
	}

	// Assign values to zkProof
	zkProof  = &proof{
		CompressedR:	compressedR,
		QaPrime:		&ecdsa.PublicKey{
			Curve:		curve,
			X:			QaPrimeX,
			Y:			QaPrimeY,
		},
		Proof:			&ecdsaSignature{
			R:			new(big.Int).SetBytes(compressedRPrime),
			S:			s,
		},
	}
	return zkProof, nil
}

func VerifyZKP(zkProof *proof, publicKey *ecdsa.PublicKey, message [][]byte) bool {

	// Print messages
	for _, slice := range message {
		fmt.Printf("Messages to be used in ZKP verification: %s\n", slice)
	}

	// 1.1 - uncompress signature.r to retrieve x and y-coordinate
	coordX, coordY, err := uncompressPoint(curve, zkProof.CompressedR)
	if err != nil {
		fmt.Errorf("error recovering y-coordinate from R: %s\n", err)
		return false
	}

	// 1.2 - Create a valid point on the curve
	RPoint := &ecdsaPoint{
		X:     coordX,
		Y:     coordY,
	}

	// 1.3 - Verify if RPoint is on curve
	if !curve.IsOnCurve(RPoint.X, RPoint.Y) {
		fmt.Errorf("Point is not on Curve!!\n")
		return false
	}

	// 2 - Compute h and h'
	// TODO: Include pub keys on hash e.g.: HASH(Qa' || m) 
	m		:= Hash(string(message[0]))
	mPrime	:= Hash(string(message[1]))

	// 3 - First verification consists in Verifying if Qa' = (m * G) + (r * Qa)
	// 3.1 - m * G 
	stp1X, stp1Y := curve.ScalarBaseMult(m.Bytes())

	// 3.2 - r * Qa
	stp2X, stp2Y := curve.ScalarMult(publicKey.X, publicKey.Y, RPoint.X.Bytes())

	// 3.3 - m * G + r * Qa
	finalX, finalY := curve.Add(stp1X, stp1Y, stp2X, stp2Y)

	// 3.4 - Parse coords to a point
	var calcQaPrime ecdsa.PublicKey
	calcQaPrime = ecdsa.PublicKey{
		Curve: curve,
		X:     finalX,
		Y:     finalY,
	}

	// 3.5 - Compare zkProof.QaPrime with Calculated QaPrime
	fmt.Printf("\nTEST 1: Comparing zkProof.QaPrime with calculated QaPrime ((m * G) + (r * Qa)): \n")
	fmt.Println(`zkProof.QaPrime.X: `, zkProof.QaPrime.X)
	fmt.Println(`Calculated Qa'.X : `, calcQaPrime.X)
	if (zkProof.QaPrime.X.Cmp(calcQaPrime.X) != 0) {
		fmt.Println(`Qa' x-coordinates does not match!!!`)
		return false
	} else {
		fmt.Println(`Qa' x-coordinates matches!!!`)
	}
	fmt.Println(`zkProof.QaPrime.Y: `, zkProof.QaPrime.Y)
	fmt.Println(`Calculated Qa'.Y : `, calcQaPrime.Y)
	if (zkProof.QaPrime.Y.Cmp(calcQaPrime.Y) != 0) {
		fmt.Println(`Qa' y-coordinates does not match!!!`)
		return false
	} else {
		fmt.Println(`Qa' y-coordinates matches!!!`)
	}

	// 4 - Second verification is to verify if s' * R' = (m' * R) + (r' * Qa')

	// 4.1 - s' * R' 
	// Uncompress RPrime
	uncX, uncY, err := uncompressPoint(curve, zkProof.Proof.R.Bytes())
	if err != nil {
		fmt.Errorf("Error decompressing RPrime point: %s\n", err)
		return false
	}

	// 4.2 - Verify if uncompressed RPrime is on curve
	if !curve.IsOnCurve(uncX, uncY) {
		fmt.Errorf("Uncompressed RPrime is not on Curve!!\n")
		return false
	}

	// 4.3 - Compute s' * R' 
	leftSideX, leftSideY := curve.ScalarMult(uncX, uncY, zkProof.Proof.S.Bytes())
	
	// 4.4 - (m' * R)
	NewX, NewY := curve.ScalarMult(RPoint.X, RPoint.Y, mPrime.Bytes())

	// 4.5 - r' * Qa'
	rightSideX, rightSideY := curve.ScalarMult(zkProof.QaPrime.X, zkProof.QaPrime.Y, uncX.Bytes())
	
	// 4.6 - (m' * R) + (r' * Qa')
	lastX, lastY := curve.Add(NewX, NewY, rightSideX, rightSideY)

	// 4.7 - Compare left side with right side equation
	fmt.Printf("\n")
	fmt.Println(`TEST 2: s' * R' = (m' * R) + (r' * Qa'): `)
	if (leftSideX.Cmp(lastX) != 0) || (leftSideY.Cmp(lastY) != 0) {
		fmt.Errorf("TEST 2 FAILED!!!!!\n")
		return false
	}
	fmt.Println("TEST 2 Successful!!!!!")

	return true
}

func ecdsaSign(privateKey *ecdsa.PrivateKey, message []byte) (r, s *big.Int, err error) {

	fmt.Println("Message to be signed: ", string(message))

	// Step 1: Generate a random nonce (k)
	k, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		fmt.Errorf("Error generating random nonce: %s\n", err)
		return nil, nil, err
	}

	// Compute R = k * G and set r as the x-coordinate of R
	rx, ry := curve.ScalarBaseMult(k.Bytes())

	// Compress R point
	compressedR, err := compressPoint(curve, rx, ry)
	if err != nil {
		fmt.Println("Error compressing point:", err)
	}

	// Test compressed R point
	testx, testY, err := uncompressPoint(curve, compressedR)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		if testx.Cmp(rx) != 0 || testY.Cmp(ry) != 0 {
			fmt.Println("Uncompressed coordinates does not match!")
		} else {
			fmt.Println("Uncompressed coordinates matches!")
		}
	}

	// Step 3: Compute the hash of the message (m)
	// 3.1 convert public key to string
	// pubkey := pubkey2String(privateKey.PublicKey)
	// 3.2 generate hash (pubkey || message)
	m := Hash(string(message))

	// Step 4: Compute s = k^(-1) * (m + da * r)
	invK := new(big.Int).ModInverse(k, curve.Params().N)
	s = new(big.Int).Mul(privateKey.D, testx)
	s.Add(s, m)
	s.Mul(s, invK)
	s.Mod(s, curve.Params().N)

	// Verify the signature using the public key
	verified := ecdsa.Verify(&privateKey.PublicKey, m.Bytes(), testx, s)
	if verified {
		fmt.Println("Signature is valid.")
	} else {
		fmt.Println("Signature is not valid.")
	}

	// Test section to verify if s * R = (m * G) + (r * Qa). This also needs to be eq Qa'
	// s * R
	step1X, step1Y := curve.ScalarMult(testx, testY, s.Bytes())

	// m * G 
	step2X, step2Y := curve.ScalarBaseMult(m.Bytes())

	// (r * Qa)
	step3X, step3Y := curve.ScalarMult(privateKey.PublicKey.X, privateKey.PublicKey.Y, testx.Bytes())

	// (m * G) + (r * Qa)
	step4X, step4Y := curve.Add(step2X, step2Y, step3X, step3Y)

	fmt.Println(`validation: s * R == (m * G) + (r * Qa)`)
	if (step1X.Cmp(step4X) == 0) &&  (step1Y.Cmp(step4Y) == 0) {
		fmt.Println(`Validation successfull!`)
		// return true
	} else {
		fmt.Println(`Validation Failed!`)
	}

	resultingR := new(big.Int).SetBytes(compressedR)
	return resultingR, s, nil
}

// HELPER Functions

func compressPoint(curve elliptic.Curve, x, y *big.Int) ([]byte, error) {

	compressedPoint := elliptic.MarshalCompressed(curve, x, y)
	if compressedPoint == nil {
		return nil, fmt.Errorf("failed to marshal point")
	}

	return compressedPoint, nil
}

func uncompressPoint(curve elliptic.Curve, compressedPoint []byte) (*big.Int, *big.Int, error) {

	x, y := elliptic.UnmarshalCompressed(curve, compressedPoint)
	if y == nil {
		return nil, nil, fmt.Errorf("failed to unmarshal compressed point")
	}

	return x, y, nil
}

// Given string, return big int
func Hash(s string) *big.Int {

	hPrime := sha256.Sum256([]byte(s))
	m := new(big.Int).SetBytes(hPrime[:])

    return m
}

// Given a x coord from a point in elliptic curve, return the possible y values
func getYCoordinates(x *big.Int) (*big.Int, *big.Int, error) {

	// Calculate y^2 = x^3 + a*x + b (mod p)
	// x^3
	xSquared := new(big.Int).Mul(x, x)
	xCubed := new(big.Int).Mul(xSquared, x)

	a := big.NewInt(-3)
	
	// ySquared = x^3 + a*x + b (mod p)
	ySquared := new(big.Int).Add(xCubed, new(big.Int).Mul(a, x))
	ySquared.Add(ySquared, curve.Params().B)
	ySquared.Mod(ySquared, curve.Params().P)

	// Calculate the square root of y^2 to get y (mod p)
	y := new(big.Int).ModSqrt(ySquared, curve.Params().P)
	if y == nil {
		return nil, nil, fmt.Errorf("no square root exists for the given x-coordinate on the P-256 curve")
	}

	// calculate the second y value
	y2 := new(big.Int).Neg(y)
	y2.Mod(y2, curve.Params().P)

	return y, y2, nil
}

// Qa' = (m * G) + (r * Qa)
func checkYCoordinates(y1, y2, r, s, m *big.Int, qa *ecdsa.PublicKey) *big.Int {

    stp1X, stp1Y := qa.Curve.ScalarBaseMult(m.Bytes())

	var currentY *big.Int

	for i:=1; i<= 2; i++ {
		if i == 1 {
			currentY = y1
		} else {
			currentY = y2
		}
		   // Calculate QaPrime for y
		   QaPrimeX, QaPrimeY := curve.ScalarMult(r, currentY, s.Bytes())
		   QaPrime := &ecdsa.PublicKey{
			   Curve: curve,
			   X:     QaPrimeX,
			   Y:     QaPrimeY,
		   }

	   	   // Calculate the first verification value: (m * G) + (r * Qa)
		   stp2X, stp2Y := qa.Curve.ScalarMult(qa.X, qa.Y, r.Bytes())
		   finalX, finalY := qa.Curve.Add(stp1X, stp1Y, stp2X, stp2Y)
	   
		   // Compare Qa' with the calculated value for y
		   if finalX.Cmp(QaPrime.X) == 0 && finalY.Cmp(QaPrime.Y) == 0 {
			   return currentY
		   }
	}

    return nil
}