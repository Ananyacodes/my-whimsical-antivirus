package main
import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)
const url = "https://raw.githubusercontent.com/Ananyacodes/rules/main/rules.yar"
func downloadFile() {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Download failed:", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Println("Download failed: HTTP status", resp.Status)
		return
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Read failed:", err)
		return
	}
	hash := sha256.Sum256(data)
	hashStr := fmt.Sprintf("%x", hash)
	lastHash, _ := os.ReadFile("last_hash.txt")
	if string(lastHash) == hashStr {
		fmt.Println("No update needed.")
		return
	}
	filename := fmt.Sprintf("rules_%d.yar", time.Now().Unix())
	// ensure rules directory exists (relative to src/)
	if err := os.MkdirAll("../rules", 0755); err != nil {
		fmt.Println("Failed to create rules directory:", err)
		return
	}
	if err := os.WriteFile("../rules/"+filename, data, 0644); err != nil {
		fmt.Println("Failed to write rules file:", err)
		return
	}
	if err := os.WriteFile("last_hash.txt", []byte(hashStr), 0644); err != nil {
		fmt.Println("Failed to write last_hash:", err)
		return
	}
	fmt.Println("Rules updated:", filename)
}
func handler(w http.ResponseWriter, r *http.Request) {
	downloadFile()
	fmt.Fprintf(w, "Update triggered\n")
}
func main() {
	http.HandleFunc("/update", handler)
	fmt.Println("Server running on :8080")
	http.ListenAndServe(":8080", nil)
}