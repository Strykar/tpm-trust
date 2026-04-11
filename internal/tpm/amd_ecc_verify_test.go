package tpm

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/loicsikidi/attest"
	"github.com/loicsikidi/attest/endorsement"
)

// Old AMDTPM ECC root CA (PRINTABLESTRING encoding, UTCTIME dates)
const amdECCRootOld = `-----BEGIN CERTIFICATE-----
MIIDAjCCAqigAwIBAgIQI0UiAdQcWrBkAyvSPxWP7zAKBggqhkjOPQQDAjB2MRQw
EgYDVQQLEwtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxEjAQBgNVBAcTCVN1bm55
dmFsZTELMAkGA1UECBMCQ0ExHzAdBgNVBAoTFkFkdmFuY2VkIE1pY3JvIERldmlj
ZXMxDzANBgNVBAMTBkFNRFRQTTAeFw0xNjAxMDEwNTAwMDBaFw00MTAxMDEwNTAw
MDBaMHYxFDASBgNVBAsTC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzESMBAGA1UE
BxMJU3Vubnl2YWxlMQswCQYDVQQIEwJDQTEfMB0GA1UEChMWQWR2YW5jZWQgTWlj
cm8gRGV2aWNlczEPMA0GA1UEAxMGQU1EVFBNMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEKLNGw0F3uq7kcoZazSAm46NUyiIJC5DgNAPo1CfrPsn3UtRni1DxC1xa
sMtvIo3jAVHZlVsmAT1g0r5XiNb5mqOCARYwggESMA4GA1UdDwEB/wQEAwIBBjAj
BgkrBgEEAYI3FSsEFgQU8hrQ+OijBunLzTh+hnJjF9vBvrkwHQYDVR0OBBYEFPIa
0Pjoowbpy804foZyYxfbwb65MA8GA1UdEwEB/wQFMAMBAf8wOAYIKwYBBQUHAQEE
LDAqMCgGCCsGAQUFBzABhhxodHRwOi8vZnRwbS5hbWQuY29tL3BraS9vY3NwMCwG
A1UdHwQlMCMwIaAfoB2GG2h0dHA6Ly9mdHBtLmFtZC5jb20vcGtpL2NybDBDBgNV
HSAEPDA6MDgGCisGAQQBnHhlFQowKjAoBggrBgEFBQcCARYcaHR0cHM6Ly9mdHBt
LmFtZC5jb20vcGtpL2NwczAKBggqhkjOPQQDAgNIADBFAiEAgaCRgPGIA9/8xEVy
tJ1YK0ERBDGHxPT0igzycASqDhACIDWbPtOXQG3Z4W09OjRtWwLwdCEkelKfPazb
yhIHIT4m
-----END CERTIFICATE-----`

// New AMDTPM ECC root CA (UTF8STRING encoding, GENERALIZEDTIME dates)
const amdECCRootNew = `-----BEGIN CERTIFICATE-----
MIIDBTCCAqygAwIBAgIQI0UiAdQcWrBkAyvSPxWP7zAKBggqhkjOPQQDAjB2MRQw
EgYDVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxEjAQBgNVBAcMCVN1bm55
dmFsZTELMAkGA1UECAwCQ0ExHzAdBgNVBAoMFkFkdmFuY2VkIE1pY3JvIERldmlj
ZXMxDzANBgNVBAMMBkFNRFRQTTAiGA8yMDE2MDEwMTA1MDAwMFoYDzIwNDEwMTAx
MDUwMDAwWjB2MRQwEgYDVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxEjAQ
BgNVBAcMCVN1bm55dmFsZTELMAkGA1UECAwCQ0ExHzAdBgNVBAoMFkFkdmFuY2Vk
IE1pY3JvIERldmljZXMxDzANBgNVBAMMBkFNRFRQTTBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABCizRsNBd7qu5HKGWs0gJuOjVMoiCQuQ4DQD6NQn6z7J91LUZ4tQ
8QtcWrDLbyKN4wFR2ZVbJgE9YNK+V4jW+ZqjggEWMIIBEjAOBgNVHQ8BAf8EBAMC
AQYwIwYJKwYBBAGCNxUrBBYEFPIa0Pjoowbpy804foZyYxfbwb65MB0GA1UdDgQW
BBTyGtD46KMG6cvNOH6GcmMX28G+uTAPBgNVHRMBAf8EBTADAQH/MDgGCCsGAQUF
BwEBBCwwKjAoBggrBgEFBQcwAYYcaHR0cDovL2Z0cG0uYW1kLmNvbS9wa2kvb2Nz
cDAsBgNVHR8EJTAjMCGgH6AdhhtodHRwOi8vZnRwbS5hbWQuY29tL3BraS9jcmww
QwYDVR0gBDwwOjA4BgorBgEEAZx4ZRUKMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8v
ZnRwbS5hbWQuY29tL3BraS9jcHMwCgYIKoZIzj0EAwIDRwAwRAIgdC//Fcx0tGsf
HFjnzGiI77v83f5UkEFaTtHmodwAqkUCIHZ+ONVyeqVYIkRFWGl9GTnhSfvmghKj
Ra64ryoheLlO
-----END CERTIFICATE-----`

func mustParsePEM(t *testing.T, name, pemData string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		t.Fatalf("%s: failed to decode PEM", name)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("%s: failed to parse certificate: %v", name, err)
	}
	return cert
}

// TestAMDECCRootEncodingVerify fetches the ECC EK certificate from the local
// AMD fTPM and verifies it against both the old (PRINTABLESTRING) and new
// (UTF8STRING) versions of the AMDTPM ECC root CA.
//
// This test requires a physical AMD TPM and is skipped otherwise.
// Run it with: go test -v -run TestAMDECCRootEncodingVerify ./internal/tpm/
func TestAMDECCRootEncodingVerify(t *testing.T) {
	tpm, err := attest.OpenTPM()
	if err != nil {
		t.Skipf("no TPM available: %v", err)
	}
	t.Cleanup(func() { _ = tpm.Close() })

	tpmInfo, err := tpm.Info()
	if err != nil {
		t.Fatalf("failed to get TPM info: %v", err)
	}

	if tpmInfo.Manufacturer.ASCII != "AMD" && tpmInfo.Manufacturer.ASCII != "AMD " {
		t.Skipf("not an AMD TPM (manufacturer: %q)", tpmInfo.Manufacturer.ASCII)
	}

	t.Logf("TPM manufacturer: %s (%s)", tpmInfo.Manufacturer.Name, tpmInfo.Manufacturer.ASCII)

	// Get the ECC EK and its certificate URL
	ek, err := endorsement.Get(tpm.Tpm(), endorsement.GetConfig{
		Template: endorsement.TemplateECC,
		Info:     *tpmInfo,
	})
	if err != nil {
		t.Skipf("endorsement.Get(ECC) failed: %v", err)
	}

	if ek.CertificateURL == "" {
		t.Skip("no ECC EK certificate URL available")
	}

	t.Logf("ECC EK certificate URL: %s", ek.CertificateURL)

	// Fetch the ECC EK leaf certificate
	ekCert, err := fetchCertFromURL(context.Background(), ek.CertificateURL, http.DefaultClient)
	if err != nil {
		t.Fatalf("failed to fetch ECC EK certificate: %v", err)
	}

	t.Logf("EK cert subject:    %s", ekCert.Subject)
	t.Logf("EK cert issuer:     %s", ekCert.Issuer)
	t.Logf("EK cert RawIssuer:  %x", ekCert.RawIssuer)

	// Parse both root CA versions
	rootOld := mustParsePEM(t, "old-root", amdECCRootOld)
	rootNew := mustParsePEM(t, "new-root", amdECCRootNew)

	t.Logf("Old root RawSubject: %x", rootOld.RawSubject)
	t.Logf("New root RawSubject: %x", rootNew.RawSubject)

	// Fetch intermediate cert(s) from the EK cert's AIA IssuingCertificateURL
	var intermediates []*x509.Certificate
	if len(ekCert.IssuingCertificateURL) > 0 {
		for _, aiaURL := range ekCert.IssuingCertificateURL {
			t.Logf("Fetching intermediate from AIA: %s", aiaURL)
			intCert, err := fetchCertFromURL(context.Background(), aiaURL, http.DefaultClient)
			if err != nil {
				t.Logf("  failed to fetch intermediate: %v", err)
				continue
			}
			t.Logf("  intermediate subject: %s", intCert.Subject)
			t.Logf("  intermediate issuer:  %s", intCert.Issuer)
			t.Logf("  intermediate RawIssuer:  %x", intCert.RawIssuer)
			t.Logf("  intermediate RawSubject: %x", intCert.RawSubject)
			intermediates = append(intermediates, intCert)

			// Follow the chain: if this intermediate has its own AIA, fetch that too
			for _, parentURL := range intCert.IssuingCertificateURL {
				t.Logf("Fetching parent from AIA: %s", parentURL)
				parentCert, err := fetchCertFromURL(context.Background(), parentURL, http.DefaultClient)
				if err != nil {
					t.Logf("  failed to fetch parent: %v", err)
					continue
				}
				t.Logf("  parent subject: %s", parentCert.Subject)
				t.Logf("  parent issuer:  %s", parentCert.Issuer)
				t.Logf("  parent RawIssuer:  %x", parentCert.RawIssuer)
				t.Logf("  parent RawSubject: %x", parentCert.RawSubject)
				intermediates = append(intermediates, parentCert)
			}
		}
	} else {
		t.Log("No AIA IssuingCertificateURL in EK cert")
	}

	// Test verification against each root
	roots := []struct {
		name string
		cert *x509.Certificate
	}{
		{"old-root (PRINTABLESTRING)", rootOld},
		{"new-root (UTF8STRING)", rootNew},
	}

	for _, root := range roots {
		t.Run(root.name, func(t *testing.T) {
			rootPool := x509.NewCertPool()
			rootPool.AddCert(root.cert)

			intPool := x509.NewCertPool()
			for _, ic := range intermediates {
				intPool.AddCert(ic)
			}

			// Test 1: Raw DN byte comparison at each link in the chain
			if len(intermediates) > 0 {
				ekToInt := string(ekCert.RawIssuer) == string(intermediates[0].RawSubject)
				t.Logf("EK.RawIssuer == intermediate.RawSubject (binary DN match): %v", ekToInt)

				// Find the intermediate that chains to the root
				for i, ic := range intermediates {
					intToRoot := string(ic.RawIssuer) == string(root.cert.RawSubject)
					t.Logf("intermediate[%d].RawIssuer == root.RawSubject (binary DN match): %v", i, intToRoot)
				}
			} else {
				directMatch := string(ekCert.RawIssuer) == string(root.cert.RawSubject)
				t.Logf("EK.RawIssuer == root.RawSubject (binary DN match): %v", directMatch)
			}

			// Test 2: Full x509.Verify with critical extensions cleared
			ekCopy := *ekCert
			ekCopy.UnhandledCriticalExtensions = nil

			opts := x509.VerifyOptions{
				Roots:         rootPool,
				Intermediates: intPool,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			}

			chains, err := ekCopy.Verify(opts)
			if err != nil {
				t.Errorf("FAIL: cert.Verify() with %s: %v", root.name, err)
				return
			}
			t.Logf("PASS: cert.Verify() with %s succeeded (chain length: %d)", root.name, len(chains[0]))
		})
	}
}
