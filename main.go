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
	// "strings"

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
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("Error generating ECDSA key pair: %s\n", err)
		return
	}

	// fmt.Printf("Generating ECDSA signature:\n")

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
	fmt.Printf("Token payload signed.\n")
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
	fmt.Printf("Encode ZKP of ECDSA signature:\n")
	zkProofJSON, err := json.Marshal(zkProof)
	if err != nil {
		fmt.Printf("Error encoding zero-knowledge proof to JSON: %s\n", err)
		return
	}
	// fmt.Printf("Proof generated: %s\n", fmt.Sprintf("%s", zkProofJSON))

	// Encode the zero-knowledge proof JSON to base64
	zkProofBase64 := base64.StdEncoding.EncodeToString(zkProofJSON)
	fmt.Printf("Encoded proof (Base64): %s\n", zkProofBase64)
	fmt.Printf("-------------------\n\n")
}

func GenerateZKP(privateKey *ecdsa.PrivateKey, signature, message []byte) (zkProof *proof, err error) {

	zkProof = &proof{}
	// curve := privateKey.Curve

	// Calculate Qa' = signature.s * R
	// 
	// Necessary retrieve y-coord from compact R point:
	// 
	// 1 - Extract r and s from the original ECDSA signature
	asn1Sig := new(ecdsaSignature)
	_, err = asn1.Unmarshal(signature, asn1Sig)
	if err != nil {
		return nil, fmt.Errorf("error parsing ASN.1 signature: %s", err)
	}

	// 2 - Recover the y-coordinate from the signature.r (x-coordinate)
	// i.e. given X and curve equation, retrieve Y
	coodY, err := getYCoordinate(asn1Sig.R, curve)
	if err != nil {
		return nil, fmt.Errorf("error recovering y-coordinate from R: %s", err)
	}
	// fmt.Println("Calculated Y-coord of R point: ", coodY)

	// 3 - Create a valid point on the curve
	RPoint := &ecdsa.PublicKey{
		Curve: curve,
		X:     asn1Sig.R,
		Y:     coodY,
	}
	// Verify if RPoint is on curve
	if !curve.IsOnCurve(RPoint.X, RPoint.Y) {
		return nil, fmt.Errorf("Point is not on Curve!!\n")
	}
	fmt.Printf("Point is on Curve!\n")

	// Using R point, 
	// Compute Qa' = R * signature.s
	// Here, R act as Generator
	QaPrimeX, QaPrimeY := curve.ScalarMult(RPoint.X, RPoint.Y, asn1Sig.S.Bytes())
	fmt.Println(`Qa': `, QaPrimeX, QaPrimeY)
	
	// Create Qa' and assign to zkProof
	zkProof.QaPrime = &ecdsa.PublicKey{
		Curve: curve,
		X:     QaPrimeX,
		Y:     QaPrimeY,
	}

	// Compute h' = HASH(Qa' || m) or HASH(m) (?)
	// m := Hash(asn1Sig.R.String() + fmt.Sprintf("%s", message))
	m := Hash(string(message))
	// fmt.Printf("msg 1 : %s\n ", message)

	// Generate new nonce k'
	kPrime, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		return nil, fmt.Errorf("error generating new nonce: %s", err)
	}

	// Compute R' such that R' = k' * R
	RPrimeX, RPrimeY := curve.ScalarMult(RPoint.X, RPoint.Y, kPrime.Bytes())


	/////// TEST
	// (R' * m') / k' = m' * R

	// (R' * m')
	NewX, NewY := curve.ScalarMult(RPrimeX, RPrimeY, m.Bytes())
	// fmt.Println("R * message: ", NewX, NewY)

	// k ^-1
	invK := new(big.Int).ModInverse(kPrime, curve.Params().N)
	// fmt.Println("k^-1: ", invK)

	// (R' * m') / k'
	LeftX, LeftY := curve.ScalarMult(NewX, NewY, invK.Bytes())
	// fmt.Println("k^-1 * m' * R: ", LeftX, LeftY)

	// m' * R
	rightX, rightY := curve.ScalarMult(RPoint.X, RPoint.Y, m.Bytes())
	// fmt.Println("rightX rightY: ", rightX, rightY)

	// check if left == right

		// fmt.Println(`Right = (R' * m') / k'`)
		// fmt.Println("rightX, rightY: ", rightX, rightY)
		// fmt.Println("LeftX, LeftY: ", LeftX, LeftY)
		// fmt.Println(`Left = m' * R`)
		fmt.Println(`(R' * m') / k' = m' * R validation result: `)
		// check
		if (LeftX.Cmp(rightX) == 0) && (LeftY.Cmp(rightY) == 0) {
			fmt.Printf("%t\n\n",true)
		} else {
			fmt.Printf("%t\n\n",false)
		}

	////////


	// Compute s' = k'^{-1}(m + signature.S * r')
	// k'^{-1}
	invK = new(big.Int).ModInverse(kPrime, curve.Params().N)
	s := new(big.Int).Mul(asn1Sig.S, RPrimeX)
	s.Add(s, m)
	s.Mul(s, invK)
	s.Mod(s, curve.Params().N)
	fmt.Println("S linha: ", s)

	// Feito isso, gera e retorna o resultado, que é: Qa', (R', s')
	// Imagino que deva descartar o RPrimeY, como feito por padrao na assinatura ECDSA
	return &proof{
		QaPrime: &ecdsa.PublicKey{
			Curve: curve,
			X:     QaPrimeX,
			Y:     QaPrimeY,
		},
		RPrimeX: RPrimeX,
		RPrimeY: RPrimeY,
		sPrime:  s,
	}, nil
}

func VerifyZKP(zkProof *proof, signature []byte, publicKey *ecdsa.PublicKey, message []byte) bool {
	
	// curve := publicKey.Curve

	// 1 - Extract r and s from the ECDSA signature
	asn1Sig := new(ecdsaSignature)
	_, err := asn1.Unmarshal(signature, asn1Sig)
	if err != nil {
		return false
	}

	// Compute h' = HASH(Qa' || m) or HASH(m) (?)
	// m := Hash(asn1Sig.R.String() + fmt.Sprintf("%s", message))
	m := Hash(string(message))
	fmt.Println(`Qa' input VerifyZKP: `, zkProof.QaPrime)

	// Verify if Qa' = (m * G) + (r * Qa)
	// m * G 
	stp1X, stp1Y := curve.ScalarBaseMult(m.Bytes())
	// check if m * G is the same in ecdsa sign and zkp verification
	fmt.Println("step1 = m * G :", stp1X, stp1Y)

	// check if asn1Sig.R == rx
	// fmt.Println("asn1Sig.R :", asn1Sig.R) // Checked and passed

	// r * Qa
	stp2X, stp2Y := curve.ScalarMult(publicKey.X, publicKey.Y, asn1Sig.R.Bytes())
	fmt.Println("step2 = (r * Qa) :", stp2X, stp2Y) // Checked and passed

	// m * G + r * Qa
	finalX, finalY := curve.Add(stp1X, stp1Y, stp2X, stp2Y)
	fmt.Println("step3 = (m * G) + (r * Qa) : ", finalX, finalY)

	var comparison ecdsa.PublicKey
	comparison = ecdsa.PublicKey{
		Curve: curve,
		X:     finalX,
		Y:     finalY,
	}
	// fmt.Println("Qa (first pubkey): ", publicKey)
	fmt.Println("Calculated Qa Linha: ", comparison)

	// check
	fmt.Println(`Result of comparing QAPrime with calculated Qa': `)
	if (zkProof.QaPrime.X.CmpAbs(comparison.X) == 0) &&  (zkProof.QaPrime.Y.CmpAbs(comparison.Y) == 0) {
		fmt.Println(`zkProof.QaPrime == Qa' calculado!`)
		// return true
	}


	// verify if s' * R' = (m * R) + (r' * Qa')

	// s' * R'
	leftSideX, leftSideY := curve.ScalarMult(zkProof.RPrimeX, zkProof.RPrimeY, zkProof.sPrime.Bytes())
	
	// 2 - Recover the y-coordinate from the signature.r (x-coordinate)
	// i.e. given X and curve equation, retrieve Y
	coodY, err := getYCoordinate(asn1Sig.R, curve)
	if err != nil {
		fmt.Errorf("error recovering y-coordinate from R: %s", err)
		return false
	}
	
	// 3 - Create a valid point on the curve
	calcR := &ecdsa.PublicKey{
		Curve: curve,
		X:     asn1Sig.R,
		Y:     coodY,
	}
	// Verify if RPoint is on curve
	if !curve.IsOnCurve(calcR.X, calcR.Y) {
		fmt.Errorf("calcR Point is not on Curve!!\n")
		return false
	}

	// m * signature.R
	NewX, NewY := curve.ScalarMult(calcR.X, calcR.Y, m.Bytes())

	// signature.R' * Qa'
	rightSideX, rightSideY := curve.ScalarMult(zkProof.QaPrime.X, zkProof.QaPrime.Y, zkProof.RPrimeX.Bytes())
	lastX, lastY := curve.Add(NewX, NewY, rightSideX, rightSideY)

	// check
	
	// fmt.Println("X comparison: ", leftSideX.CmpAbs(lastX))
	// fmt.Println("Y comparison: ", leftSideY.CmpAbs(lastY))

	if (leftSideX.CmpAbs(lastX) == 0) && (leftSideY.CmpAbs(lastY) == 0) {
		fmt.Println("Success!!!!!")
		return true
	}

	fmt.Println("FAIL!!!!!")
	return false
}

func ecdsaSign(privateKey *ecdsa.PrivateKey, message []byte) (r, s *big.Int, err error) {

	// Step 1: Generate a random nonce (k)
	k, _ := rand.Int(rand.Reader, curve.Params().N)

	// Compute R = k * G and set r as the x-coordinate of R
	rx, ry := curve.ScalarBaseMult(k.Bytes())
	// fmt.Println("cooords: ", rx, ry)

	// Step 3: Compute the hash of the message (m)
	// 3.1 convert public key to string
	// pubkey := pubkey2String(privateKey.PublicKey)
	// 3.2 generate hash (pubkey || message)
	m := Hash(string(message))

	// Step 4: Compute s = k^(-1) * (m + da * r)
	invK := new(big.Int).ModInverse(k, curve.Params().N)
	s = new(big.Int).Mul(privateKey.D, rx)
	s.Add(s, m)
	s.Mul(s, invK)
	s.Mod(s, curve.Params().N)

	// Print the signature values
	fmt.Println("Signature:")
	fmt.Println("R:", rx)
	fmt.Println("S:", s)

	// Verify the signature using the public key
	verified := ecdsa.Verify(&privateKey.PublicKey, m.Bytes(), rx, s)
	if verified {
		fmt.Println("Signature is valid.")
	} else {
		fmt.Println("Signature is not valid.")
	}

	
	// TEst section to verify if s * R = (m * G) + (r * Qa)
	// this also needs to be eq Qa'

	// s * R
	step1X, step1Y := curve.ScalarMult(rx, ry, s.Bytes())

	// m * G 
	step2X, step2Y := curve.ScalarBaseMult(m.Bytes())
	// check if m * G is the same in ecdsa sign and zkp verification

	// check if asn1Sig.R == rx
	// fmt.Println("rx :", rx) // Checked and passed

	// (r * Qa)
	step3X, step3Y := curve.ScalarMult(privateKey.PublicKey.X, privateKey.PublicKey.Y, rx.Bytes())

	// (m * G) + (r * Qa)
	step4X, step4Y := curve.Add(step2X, step2Y, step3X, step3Y)

	// fmt.Println("step1 = s * r :",step1X, step1Y)
	// fmt.Println("step2 = m * G :", step2X, step2Y)
	// fmt.Println("step3 = (r * Qa) :", step3X, step3Y) 
	// fmt.Println("step4 = (m * G) + (r * Qa)", step4X, step4Y)
	fmt.Println("validation: Step1 == step4 == Qa Linha")
	fmt.Println("step1x, step1y", step1X, step1Y)
	fmt.Println("step4x, step4y", step4X, step4Y)
	// PASSED

	return rx, s, nil
}

// HELPER Functions

func serializePoint(point *ecdsa.PublicKey) []byte {
	data := elliptic.Marshal(point.Curve, point.X, point.Y)
	return data
}

func getYCoordinate(x *big.Int, curve elliptic.Curve) (*big.Int, error) {

	// fmt.Printf("Extracting y coord from point: %s\n", x)

	// Calculate y^2 = x^3 + a*x + b (mod p)
	xSquared := new(big.Int).Mul(x, x)
	xCubed := new(big.Int).Mul(xSquared, x)
	a := big.NewInt(-3)
	b := curve.Params().B
	ySquared := new(big.Int).Add(xCubed, new(big.Int).Mul(a, x))
	ySquared.Add(ySquared, b)
	ySquared.Mod(ySquared, curve.Params().P)

	// Calculate the square root of y^2 to get y (mod p)
	y := new(big.Int).ModSqrt(ySquared, curve.Params().P)
	if y == nil {
		return nil, fmt.Errorf("no square root exists for the given x-coordinate on the P-256 curve")
	}
	// fmt.Printf("y coord from point: %s\n", y)

	// Check if the calculated y-coordinate is even or odd
	// Adjust the sign if necessary to match the desired y-coordinate
	if y.Bit(0) != x.Bit(0) {
		y.Neg(y)
		y.Mod(y, curve.Params().P)
	}

	return y, nil
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