package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
	"regexp"
	"strconv"

	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto/sha3"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

var scanner = bufio.NewScanner(os.Stdin)

func main() {
	ethClient, err := ethclient.Dial("https://ropsten.infura.io")
	if err != nil {
		log.Fatal("Connection Error.")
	}
	fmt.Println("")
	fmt.Println("=============== Eth-Wallet for Ropsten ===============")
	for {
		renderMenu()
		scanner.Scan()
		switch scanner.Text() {
		case "0":
			privateKey, address := genWallet()
			renderWallet(privateKey, address)
			continue
		case "1":
			if result := checkBalance(ethClient); result == "" {
				continue
			}
		case "2":
			if result := transferEth(ethClient); result == "" {
				continue
			}
		case "3":
			log.Fatal("Exiting....")
		default:
			fmt.Println("")
			fmt.Println("Invalid Input")
			continue
		}
	}
}

func readAddress(who string) string {
	fmt.Println("")
	fmt.Println("Enter ", who, " AccountAddress :")
	scanner.Scan()
	address := scanner.Text()
	re := regexp.MustCompile("^0x[0-9a-fA-F]{40}$")
	if re.MatchString(address) == false {
		fmt.Println("")
		fmt.Println("Invalid Address")
		return "Error"
	}
	return address
}

func readPriKey() string {
	fmt.Println("")
	fmt.Println("Enter your Private Key : ")
	scanner.Scan()
	privateKey := scanner.Text()
	return privateKey
}

func readVal() *big.Int {
	var value *big.Int
	for {
		fmt.Println("")
		fmt.Println("Enter Values in Ether : ")
		scanner.Scan()
		stringVal := scanner.Text()
		intVal, err := strconv.Atoi(stringVal)
		if err != nil {
			continue
		}
		value = big.NewInt(int64(intVal) * 1000000000000000000)
		break
	}
	return value
}

func checkBalance(ethClient *ethclient.Client) string {
	address := readAddress("Your")
	if address == "Error" {
		return ""
	}
	convertedAddr := common.HexToAddress(address)
	balance, err := ethClient.BalanceAt(context.Background(), convertedAddr, nil)
	ethBalance := convertToEth(balance)
	if err != nil {
		fmt.Println("Connection Error..")
		return ""
	}
	fmt.Println("")
	fmt.Println("Your balance is ::::", ethBalance, " Eth")
	return "Success"
}

func transferEth(ethClient *ethclient.Client) string {

	privateKey := readPriKey()
	convertedPriKey, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		fmt.Println("Error")
		return ""
	}

	publicKey := convertedPriKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("Error")
		return ""
	}
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := ethClient.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		fmt.Println("Error")
		return ""
	}

	var to string
	var value *big.Int
	var data []byte
	gasLimit := uint64(21000)
	gasPrice, err := ethClient.SuggestGasPrice(context.Background())
	if err != nil {
		fmt.Println("Error")
		return ""
	}

	for {
		to = readAddress("Receiver")
		if to == "Error" {
			continue
		}
		break
	}

	value = readVal()
	choice := confirmOrNot()
	if choice != "Confirm" {
		return ""
	}
	toAddress := common.HexToAddress(to)
	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, data)
	chainId, err := ethClient.NetworkID(context.Background())
	if err != nil {
		fmt.Println("Error")
		return ""
	}
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainId), convertedPriKey)
	if err != nil {
		fmt.Println("Error")
		return ""
	}
	err = ethClient.SendTransaction(context.Background(), signedTx)
	if err != nil {
		fmt.Println("Error")
		return ""
	}
	fmt.Println("")
	fmt.Println("Transfer Succeeded ! : ", signedTx.Hash().Hex())
	return "Success"
}

func genWallet() (string, string) {
	priKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal("Failed to create keys")
	}
	priKeyBytes := crypto.FromECDSA(priKey)
	privateKey := hexutil.Encode(priKeyBytes)[2:]

	pubKey := priKey.Public()
	pubKeyECDSA, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("Failed to create keys")
	}
	pubKeyBytes := crypto.FromECDSAPub(pubKeyECDSA)
	hash := sha3.NewKeccak256()
	hash.Write(pubKeyBytes[1:])
	address := hexutil.Encode(hash.Sum(nil)[12:])
	return privateKey, address
}

func convertToEth(balance *big.Int) *big.Float {
	fbalance := new(big.Float)
	fbalance.SetString(balance.String())
	ethValue := new(big.Float).Quo(fbalance, big.NewFloat(math.Pow10(18)))
	return ethValue
}

func confirmOrNot() string {
	fmt.Println("")
	fmt.Println("[1] Confirm   [2] Cancel")
	scanner.Scan()
	if scanner.Text() == "1" {
		return "Confirm"
	} else if scanner.Text() == "2" {
		return "Cancel"
	} else {
		fmt.Println("Enter 1 or 2 only")
		return "Invalid"
	}
}

func renderMenu() {
	fmt.Println("")
	fmt.Println("-----------------------------------------------------------------------")
	fmt.Println("Menu:  [0] Create Wallet  [1] Check Balance  [2] Transfer Eth  [3] Exit")
	fmt.Println("-----------------------------------------------------------------------")
	fmt.Println("")
}

func renderWallet(privateKey, address string) {
	fmt.Println("")
	fmt.Println("Private Key :: ", privateKey)
	fmt.Println("")
	fmt.Println("Address :: ", address)
	fmt.Println("")
}
