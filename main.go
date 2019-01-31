package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/olekukonko/tablewriter"
	"github.com/schollz/progressbar/v2"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type PasswordFile struct {
	Passwords []Password `json:"AUTHENTIFIANT"`
}

type Password struct {
	Password string `json:"password"`
	Title    string `json:"title"`
}

type PasswordCheckResult uint8

const (
	ResultSafe        PasswordCheckResult = 0
	ResultCompromised PasswordCheckResult = 1
	ResultUnchecked   PasswordCheckResult = 2
)

func main() {
	validateArgs()

	passwordFile := fetchPasswordFile(os.Args[1])

	compromised, unchecked, safe := processPasswords(passwordFile)

	renderResults(compromised, unchecked, safe)
}

func validateArgs() {
	flag.Parse()
	if flag.NArg() < 1 || flag.Arg(0) == "" {
		log.Fatal("Usage: ./dashlane-have-i-been-pwned /path/to/passwords.json")
	}
}

func fetchPasswordFile(passwordFileLocation string) *PasswordFile {
	passwordFile := PasswordFile{}
	passwordFileBytes, err := ioutil.ReadFile(passwordFileLocation)
	if err != nil {
		log.Fatalf("Unable to read file %s", passwordFileLocation)
	}
	err = json.Unmarshal(passwordFileBytes, &passwordFile)
	if err != nil {
		log.Fatalf("Unable to parse password file. Is it valid JSON?")
	}
	return &passwordFile
}

func processPasswords(passwordFile *PasswordFile) ([]string, []string, int) {
	bar := progressbar.New(len(passwordFile.Passwords))

	var compromised []string
	var unchecked []string
	safe := 0

	for _, password := range passwordFile.Passwords {
		result := checkPasswordHash(password.Title, password.Password)
		switch result {
		case ResultCompromised:
			compromised = append(compromised, fmt.Sprintf("%s: %s", password.Title, password.Password))
			checkErr(bar.Add(1))
		case ResultUnchecked:
			unchecked = append(unchecked, password.Title)
			checkErr(bar.Add(1))
		case ResultSafe:
			safe++
			checkErr(bar.Add(1))
		default:
			checkErr(bar.Add(1))
		}
	}

	return compromised, unchecked, safe
}

func checkPasswordHash(title string, password string) PasswordCheckResult {
	hash := sha1.New()
	passwordBytes := []byte(password)
	hash.Write(passwordBytes)
	passwordHash := hex.EncodeToString(hash.Sum(nil))
	resp, err := http.Get("https://api.pwnedpasswords.com/range/" + passwordHash[:5])
	checkErr(err)
	if resp.StatusCode == 200 {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		checkErr(err)
		lines := strings.Split(strings.ToLower(string(bodyBytes)), "\n")
		for _, line := range lines {
			remoteHash := line[:35]
			if strings.EqualFold(remoteHash, passwordHash[5:40]) {
				return ResultCompromised
			}
		}
		return ResultSafe
	} else if resp.StatusCode == 429 {
		time.Sleep(1500)
		return checkPasswordHash(title, password)
	} else {
		return ResultUnchecked
	}
}

func renderResults(compromised []string, unchecked []string, safe int) {
	fmt.Println()
	fmt.Println()

	renderStatsTable(compromised, unchecked, safe)

	renderTitleTable("Compromised", compromised)
	renderTitleTable("Unchecked", unchecked)
}

func renderStatsTable(compromised []string, unchecked []string, safe int) {
	writer := tablewriter.NewWriter(os.Stdout)
	writer.SetHeaderAlignment(tablewriter.ALIGN_CENTER)
	writer.SetHeader([]string{"Stats"})
	writer.Append([]string{"Compromised", fmt.Sprintf("%v", len(compromised))})
	writer.Append([]string{"Unchecked", fmt.Sprintf("%v", len(unchecked))})
	writer.Append([]string{"Safe", fmt.Sprintf("%v", safe)})
	writer.Render()
}

func renderTitleTable(title string, values []string) {
	if len(values) > 0 {
		writer := tablewriter.NewWriter(os.Stdout)
		writer.SetHeaderAlignment(tablewriter.ALIGN_CENTER)
		writer.SetHeader([]string{title})
		for _, value := range values {
			writer.Append([]string{value})
		}
		writer.Render()
	}
}

func checkErr(err error) {
	if err != nil {
		log.Panic(err)
	}
}
