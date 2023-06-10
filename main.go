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

	"crypto/x509"
	"encoding/pem"
	"os"
)

type proof struct {
	QaPrime  *ecdsa.PublicKey
	RPrimeX  *big.Int
	RPrimeY  *big.Int
	sPrime   *big.Int
}

type ecdsaSignature struct {
	R, S *big.Int
}

var curve = elliptic.P256()

func main() {

	tokenPayload := "tokenpayload"

	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		fmt.Printf("Error generating ECDSA key pair: %s\n", err)
		return
	}

	
	// // Sign the token payload
	// hash := sha256.Sum256([]byte(tokenPayload))
	// r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	// if err != nil {
	// 	fmt.Printf("Error signing token payload: %s\n", err)
	// 	return
	// }


	fmt.Printf("Generate ECDSA signature:\n")
	r, s, err := ecdsaSign(privateKey, []byte(tokenPayload))
	if err != nil {
		fmt.Printf("Error signing token payload: %s\n", err)
		return
	}
	fmt.Printf("-------------------\n\n")

	// Encode the ECDSA signature
	signatureBytes, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		fmt.Printf("Error encoding ECDSA signature: %s\n", err)
		return
	}

	// Generate zero-knowledge proof
	// signer := &zkpSigner{privateKey}
	fmt.Printf("Generate ZKP of ECDSA signature:\n")
	zkProof, err := GenerateZKP(privateKey, signatureBytes, []byte(tokenPayload))
	if err != nil {
		fmt.Printf("Error generating zero-knowledge proof: %s\n", err)
		return
	}
	fmt.Printf("-------------------\n\n")

	// Verify zero-knowledge proof
	fmt.Printf("Verify ZKP of ECDSA signature:\n")
	publicKey := privateKey.Public()
	if !VerifyZKP(zkProof, signatureBytes, publicKey.(*ecdsa.PublicKey), []byte(tokenPayload)) {
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

func GenerateZKP(privateKey *ecdsa.PrivateKey, signature, message []byte) (zkProof *proof, err error) {

	// test values
	// var testR big.Int

	zkProof = &proof{}
	// 1 - to Calculate Qa' = signature.s * R is
	// 
	// Necessary to retrieve y-coord from compact R point:
	// 
	// 1.1 - Extract r and s from the original ECDSA signature
	asn1Sig := new(ecdsaSignature)
	_, err = asn1.Unmarshal(signature, asn1Sig)
	if err != nil {
		return nil, fmt.Errorf("error parsing ASN.1 signature: %s", err)
	}

	// 1.2 - Recover the y-coordinate from the signature.r (x-coordinate)
	// i.e. given X and curve equation, retrieve Y
	coordX, coordY, err := uncompressPoint(curve, asn1Sig.R.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error recovering y-coordinate from R: %s", err)
	}
	// fmt.Println("Calculated Y-coord of R point time: ", coordY)

	// 1.3 - Create a valid point on the curve
	RPoint := &ecdsa.PublicKey{
		Curve: curve,
		X:     coordX,
		Y:     coordY,
	}
	// Verify if RPoint is on curve
	if !curve.IsOnCurve(RPoint.X, RPoint.Y) {
		return nil, fmt.Errorf("Point is not on Curve!!\n")
	}
	// fmt.Printf("Point is on Curve!\n")

	// Using R point, 
	// 1.4 Compute Qa' = R * signature.s
	// Here, R act as Generator
	QaPrimeX, QaPrimeY := curve.ScalarMult(RPoint.X, RPoint.Y, asn1Sig.S.Bytes())
	
	// 2 - Compute h' = HASH(Qa' || m) or HASH(m) (?)
	m := Hash(string(message))

	// 3 Generate new nonce k'
	kPrime, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		return nil, fmt.Errorf("error generating new nonce: %s", err)
	}

	// 3.1 Compute R' such that R' = k' * R
	// Testing if discarding Y from scalarmult and using getYcoord can avoid problems
	RPrimeX, RPrimeY := curve.ScalarMult(RPoint.X, RPoint.Y, kPrime.Bytes())
	// RPrimeY, err := getYCoordinate(RPrimeX, curve)
	// if err != nil {
	// 	return nil, fmt.Errorf("error recovering y-coordinate from R: %s", err)
	// }
	// //////////////////


	/////// TEST
	// (R' * m') / k' = m' * R

	// (R' * m')
	NewX, NewY := curve.ScalarMult(RPrimeX, RPrimeY, m.Bytes())
	// fmt.Println("R * message: ", NewX, NewY)

	// k'^-1
	invK := new(big.Int).ModInverse(kPrime, curve.Params().N)

	// (R' * m') / k'
	LeftX, LeftY := curve.ScalarMult(NewX, NewY, invK.Bytes())

	// m' * R
	rightX, rightY := curve.ScalarMult(RPoint.X, RPoint.Y, m.Bytes())

	// Check if left == right
	fmt.Println(`GenerateZKP Validation performs: (R' * m') / k' = m' * R`)
	if (LeftX.Cmp(rightX) == 0) && (LeftY.Cmp(rightY) == 0) {
		fmt.Println(`Validation successfull!`)
	} else {
		fmt.Println(`Validation Failed!`)
	}

	////////


	// Compute s' = k'^{-1}(m + signature.S * r')
	// k'^{-1}
	invK = new(big.Int).ModInverse(kPrime, curve.Params().N)
	s := new(big.Int).Mul(asn1Sig.S, RPrimeX)
	s.Add(s, m)
	s.Mul(s, invK)
	s.Mod(s, curve.Params().N)

	// Assign values to zkProof
	zkProof  = &proof{
		QaPrime: &ecdsa.PublicKey{
			Curve: curve,
			X:     QaPrimeX,
			Y:     QaPrimeY,
		},
		RPrimeX: RPrimeX,
		RPrimeY: RPrimeY,
		sPrime:  s,
	}

	// DEBUG
	// fmt.Println(`Message': `, m)
	// fmt.Println(`Qa' ==  (R * signature.s): `)
	fmt.Println(`Generated zkProof': `, zkProof)
	// fmt.Println(`Generated Qa'.Y: `, zkProof.QaPrime.Y)
	// fmt.Println(`** rx': `, zkProof.RPrimeX)
	// fmt.Println(`ry': `, zkProof.RPrimeY)
	// fmt.Println(`s': `, s)

	// Feito isso, gera e retorna o resultado, que é: Qa', (R', s')
	// Imagino que deva descartar o RPrimeY, como feito por padrao na assinatura ECDSA
	return zkProof, nil
}

func VerifyZKP(zkProof *proof, signature []byte, publicKey *ecdsa.PublicKey, message []byte) bool {
	
	// 1 - Extract r and s from the ECDSA signature
	asn1Sig := new(ecdsaSignature)
	_, err := asn1.Unmarshal(signature, asn1Sig)
	if err != nil {
		return false
	}

	// 1.2 - Recover the y-coordinate from the signature.r (x-coordinate)
	// i.e. given X and curve equation, retrieve Y
	coordX, coordY, err := uncompressPoint(curve, asn1Sig.R.Bytes())
	if err != nil {
		fmt.Errorf("error recovering y-coordinate from R: %s", err)
		return false
	}
	// fmt.Println("Calculated Y-coord of R point time: ", coordY)

	// 1.3 - Create a valid point on the curve
	RPoint := &ecdsa.PublicKey{
		Curve: curve,
		X:     coordX,
		Y:     coordY,
	}
	// Verify if RPoint is on curve
	if !curve.IsOnCurve(RPoint.X, RPoint.Y) {
		fmt.Errorf("Point is not on Curve!!\n")
		return false
	}
	// fmt.Printf("Point is on Curve!\n")

	// Compute h' = HASH(Qa' || m) or HASH(m) (?)
	m := Hash(string(message))

	// First verification consists in Verifying if Qa' = (m * G) + (r * Qa)
	// m * G 
	stp1X, stp1Y := curve.ScalarBaseMult(m.Bytes())
	// check if m * G is the same in ecdsa sign and zkp verification
	// fmt.Println("step1 = m * G :", stp1X, stp1Y)

	// r * Qa
	stp2X, stp2Y := curve.ScalarMult(publicKey.X, publicKey.Y, RPoint.X.Bytes())
	// fmt.Println("step2 = (r * Qa) :", stp2X, stp2Y) // Checked and passed

	// m * G + r * Qa
	finalX, finalY := curve.Add(stp1X, stp1Y, stp2X, stp2Y)
	// fmt.Println("step3 = (m * G) + (r * Qa) : ", finalX, finalY)

	// Parse coords to a point
	var calcQaPrime ecdsa.PublicKey
	calcQaPrime = ecdsa.PublicKey{
		Curve: curve,
		X:     finalX,
		Y:     finalY,
	}
	// fmt.Println(`Message': `, m)
	fmt.Println(`Received Qa' (zkProof.QaPrime): `)
	fmt.Println(`Received Qa'.X: `, zkProof.QaPrime.X)
	fmt.Println(`Received Qa'.Y: `, zkProof.QaPrime.Y)
	// fmt.Println(`Calculated Qa': `)
	fmt.Println(`Calculated Qa'.X: `, calcQaPrime.X)
	fmt.Println(`Calculated Qa'.Y: `, calcQaPrime.Y)

	// check
	fmt.Println(`TEST 1: Comparing zkProof.QaPrime with calculated Qa' ((m * G) + (r * Qa)): `)
	if (zkProof.QaPrime.X.Cmp(calcQaPrime.X) != 0) || (zkProof.QaPrime.Y.Cmp(calcQaPrime.Y) != 0) {
		fmt.Println(`zkProof.QaPrime NOT EQUAL TO calculated Qa'!`)
		return false
	}
	// if zkProof.QaPrime.Equal(calcQaPrime) {
	// 	fmt.Println(`zkProof.QaPrime == calcQaPrime!`)
	// } else {
	// 	fmt.Println(`zkProof.QaPrime NOT EQUAL TO calcQaPrime!`)
	// }


	// Second verification is to verify if s' * R' = (m' * R) + (r' * Qa')

	// 1 - s' * R' - Recover the y-coordinate from the signature.r'
	// fmt.Println("** zkProof.RPrimeX value: ", zkProof.RPrimeX)
	// rPrimeY, err := getYCoordinate(zkProof.RPrimeX, curve)
	// if err != nil {
	// 	fmt.Errorf(`error recovering y-coordinate from R': %s`, err)
	// 	return false
	// }
	// fmt.Println("Calculated Y-coord of R point: ", coodY)

	// 1.1 -  Create a valid point on the curve
	// calcRPrime := &ecdsa.PublicKey{
	// 	Curve:	curve,
	// 	X:		zkProof.RPrimeX,
	// 	Y:		rPrimeY,
	// }
	fmt.Println(`zkProof.RPrimeX: `, zkProof.RPrimeX)
	fmt.Println(`zkProof.RPrimeY: `, zkProof.RPrimeY)

	// // Check if calculated ry == proof.rprimeY
	// fmt.Println(`TEST 1.5: check if proof.RPrimeY == calcRPrimeY`)
	// if (zkProof.RPrimeY.Cmp(rPrimeY) == 0) {
	// 	fmt.Println("Calculated ry' equals to  proof.ry'!!!!!")
	// } else {
	// 	fmt.Println("Calculated ry' NOT EQUAL TO  proof.ry'!!!!!")
	// }

	// 1.2 -  Verify if calcRPrime is on curve
	if !curve.IsOnCurve(zkProof.RPrimeX, zkProof.RPrimeY) {
		fmt.Errorf("zkProof.RPrime is not on Curve!!\n")
		return false
	}
	// fmt.Printf("zkProof.RPrime is on Curve!\n")

	// 1.3 - s' * R' 
	leftSideX, leftSideY := curve.ScalarMult(zkProof.RPrimeX, zkProof.RPrimeY, zkProof.sPrime.Bytes())
	
	// 2 - (m * R) - Recover the y-coordinate from the signature.r
	coordX, coordY, err = uncompressPoint(curve, asn1Sig.R.Bytes())
	if err != nil {
		fmt.Errorf("error recovering y-coordinate from R: %s", err)
		return false
	}
	
	// 2.1 - Create a valid point on the curve
	calcR := &ecdsa.PublicKey{
		Curve:	curve,
		X:		coordX,
		Y:		coordY,
	}
	// 2.2 - Verify if R is on curve
	if !curve.IsOnCurve(calcR.X, calcR.Y) {
		fmt.Errorf("calcR Point is not on Curve!!\n")
		return false
	}

	// 2.3 - m * R
	NewX, NewY := curve.ScalarMult(calcR.X, calcR.Y, m.Bytes())

	// 3 - r' * Qa'
	rightSideX, rightSideY := curve.ScalarMult(zkProof.QaPrime.X, zkProof.QaPrime.Y, zkProof.RPrimeX.Bytes())
	
	// 4 - (m * R) + (r' * Qa')
	lastX, lastY := curve.Add(NewX, NewY, rightSideX, rightSideY)

	fmt.Println(`TEST 2: s' * R' = (m * R) + (r' * Qa'): `)
	if (leftSideX.Cmp(lastX) != 0) || (leftSideY.Cmp(lastY) != 0) {
		fmt.Println("FAIL!!!!!")
		return false
	}

	fmt.Println("Success!!!!!")
	return true
}

func ecdsaSign(privateKey *ecdsa.PrivateKey, message []byte) (r, s *big.Int, err error) {

	// Step 1: Generate a random nonce (k)
	k, _ := rand.Int(rand.Reader, curve.Params().N)

	// Compute R = k * G and set r as the x-coordinate of R
	rx, ry := curve.ScalarBaseMult(k.Bytes())
	// fmt.Println("cooords: ", rx, ry)
	// Test of correctness of getYcoord func

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
	// fmt.Println("rx value: ", rx)
	// fmt.Println("uncompressed rx value: ", testx)
	// fmt.Println("ry value: ", ry)
	// fmt.Println("uncompressed rY value: ", testY)

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

	// // TEst section to verify if s * R = (m * G) + (r * Qa)
	// // this also needs to be eq Qa'

	// // s * R
	step1X, step1Y := curve.ScalarMult(testx, testY, s.Bytes())

	// // m * G 
	step2X, step2Y := curve.ScalarBaseMult(m.Bytes())
	// // check if m * G is the same in ecdsa sign and zkp verification

	// // (r * Qa)
	step3X, step3Y := curve.ScalarMult(privateKey.PublicKey.X, privateKey.PublicKey.Y, testx.Bytes())

	// (m * G) + (r * Qa)
	step4X, step4Y := curve.Add(step2X, step2Y, step3X, step3Y)

	fmt.Println(`validation: s * R == (m * G) + (r * Qa)`)
	// fmt.Println("s * R = step1x, step1y: ", step1X, step1Y)
	// fmt.Println("step4x, step4y", step4X, step4Y)
	if (step1X.Cmp(step4X) == 0) &&  (step1Y.Cmp(step4Y) == 0) {
		fmt.Println(`Validation successfull!`)
		// return true
	} else {
		fmt.Println(`Validation Failed!`)
	}

	// Print the signature values
	// fmt.Println("Signature:")
	// fmt.Println("R:", compressedR)
	// fmt.Println("S:", s)
	resultingR := new(big.Int).SetBytes(compressedR)
	return resultingR, s, nil
}

// HELPER Functions

// The way it is, using with an std ecdsa signature does not work, cause signature.r is not a compressed point.
// One alternative may be modifying this func to return both y values, that needs to be tested. 
func getYCoordinate(x *big.Int, curve elliptic.Curve) (*big.Int, error) {

	// Calculate y^2 = x^3 + a*x + b (mod p)
	// x^3
	xSquared := new(big.Int).Mul(x, x)
	xCubed := new(big.Int).Mul(xSquared, x)

	a := big.NewInt(-3)
	b := curve.Params().B
	
	// ySquared = x^3 + a*x + b (mod p)
	ySquared := new(big.Int).Add(xCubed, new(big.Int).Mul(a, x))
	ySquared.Add(ySquared, b)
	ySquared.Mod(ySquared, curve.Params().P)

	// Calculate the square root of y^2 to get y (mod p)
	y := new(big.Int).ModSqrt(ySquared, curve.Params().P)
	if y == nil {
		return nil, fmt.Errorf("no square root exists for the given x-coordinate on the P-256 curve")
	}

	// Check if the calculated y-coordinate is even or odd
	// Adjust the sign if necessary to match the desired y-coordinate
	if y.Bit(0) != x.Bit(0) {
		y.Neg(y)
		y.Mod(y, curve.Params().P)
	}

	return y, nil
}

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

func pubkey2String(pubkey ecdsa.PublicKey) string {
	// 3.1 Convert public key to PEM format
	pemBytes, err := x509.MarshalPKIXPublicKey(&pubkey)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	// 3.2 Encode PEM bytes to string
	pemString := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pemBytes,
	}))
	return pemString
}