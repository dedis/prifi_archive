package main

import (
    "fmt"
    "math/big"
    "encoding/json"
    "io/ioutil"
    "os"
)

const p = "124325339146889384540494091085456630009856882741872806181731279018491820800119460022367403769795008250021191767583423221479185609066059226301250167164084041279837566626881119772675984258163062926954046545485368458404445166682380071370274810671501916789361956272226105723317679562001235501455748016154806151119"
const q = "99656004450068572491707650369312821808187082634000238991378622176696343491115105589981816355495019598158936211590631375413874328242985824977217673016350079715590567506898528605283803802106354523568154237112165652810149860207486982093994904778268429329328161591283210109749627870113664380845204583563547255062"

func shared_secret(public, private, p *big.Int) *big.Int {
    return new(big.Int).Exp(public, private, p)
}

type PublicKeys struct {
    Keys []*big.Int `json:"public_keys"`
}

func main() {
    //P, _ := new(big.Int).SetString(p, 10)
    //G, _ := new(big.Int).SetString(q, 10)

    file, err := ioutil.ReadFile("./keys/client.json")
    if err != nil {
        fmt.Printf("Error reading file: %v\n", err)
        os.Exit(1)
    }
    
    var publicKeys PublicKeys
    err = json.Unmarshal(file, &publicKeys)
    if err != nil {
        fmt.Printf("Error unmarshaling JSON: %v\n", err)
        os.Exit(1)
    }
    fmt.Printf("%s\n", publicKeys)
}
