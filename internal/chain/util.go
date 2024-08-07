package chain

import (
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

func EtherToWei(amount float64) *big.Int {
	//ether := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	//return new(big.Int).Mul(big.NewInt(amount), ether)
	wei := math.Pow10(18) * amount
	weiAmount := new(big.Float)
	weiAmount.SetFloat64(wei)
	result := new(big.Int)
	weiAmount.Int(result)
	return result
}

func Has0xPrefix(str string) bool {
	return len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
}

func IsValidAddress(address string, checksummed bool) bool {
	if !common.IsHexAddress(address) {
		return false
	}
	return !checksummed || common.HexToAddress(address).Hex() == address
}
