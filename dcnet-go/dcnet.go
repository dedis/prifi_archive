package main

import (
    "fmt"
    "math/big"
    "math/rand"
    "encoding/json"
    "io/ioutil"
    "os"
)

const p = "124325339146889384540494091085456630009856882741872806181731279018491820800119460022367403769795008250021191767583423221479185609066059226301250167164084041279837566626881119772675984258163062926954046545485368458404445166682380071370274810671501916789361956272226105723317679562001235501455748016154806151119"
const q = "99656004450068572491707650369312821808187082634000238991378622176696343491115105589981816355495019598158936211590631375413874328242985824977217673016350079715590567506898528605283803802106354523568154237112165652810149860207486982093994904778268429329328161591283210109749627870113664380845204583563547255062"

// a few functions to make things easier
func SharedSecret(public, private, p *big.Int) *big.Int {
    return new(big.Int).Exp(public, private, p)
}

func RandBits(prsg *rand.Rand, bits int) *big.Int {
    limit := big.NewInt(0)
    limit.SetBit(limit, bits + 1, 1)
    return new(big.Int).Rand(prsg, limit)
}

// structs to unmarshal JSON data
type PublicData struct {
    PublicKeys []*big.Int `json:"public_keys"`
}

type ClientData struct {
	Id int`json:"n"`
	PrivateKey *big.Int `json:"private_key"`
}

type Client struct {
    ClientData ClientData
    PublicData PublicData
    SharedSecrets []int64
    Randoms []*rand.Rand
    Received int
    ExchangeData []*big.Int
}

func (c *Client) ComputeSecrets(publicKeys []*big.Int, p *big.Int) {
    nClients := len(publicKeys)
    secrets := make([]int64, nClients)
    randoms := make([]*rand.Rand, nClients)
    for i := 0; i < nClients; i++ {
        secrets[i] = SharedSecret(publicKeys[i], c.ClientData.PrivateKey, p).Int64()
        randoms[i] = rand.New(rand.NewSource(secrets[i]))
    }
    c.SharedSecrets = secrets
    c.Randoms = randoms

    // get ready to receive data
    c.Received = 0
    c.ExchangeData = make([]*big.Int, nClients)
    for i := 0; i < nClients; i++ {
        c.ExchangeData[i] = big.NewInt(0)
    }
}

func (c *Client) PrepareExchange(exchangeId int, text string) []*big.Int {
    slotSize := 512
    message := new(big.Int).SetBytes([]byte(text))

    nClients := len(c.PublicData.PublicKeys)
    transmission := make([]*big.Int, nClients)
    for i := 0; i < nClients; i++ {
        data := big.NewInt(0)
        for j := 0; j < nClients; j++ {
            if j != c.ClientData.Id {
                stream := c.Randoms[j]
                coin := RandBits(stream, slotSize)
                data.Xor(data, coin)
            }
        }
        if i == c.ClientData.Id {
            data.Xor(data, message)
        }
        transmission[i] = data
    }
    return transmission
}

func (c *Client) HandleExchange(exchangeId int, clientId int, data []*big.Int) []string {
    nClients := len(c.PublicData.PublicKeys)
    for i := 0; i < nClients; i++ {
        c.ExchangeData[i].Xor(c.ExchangeData[i], data[i])
    }
    c.Received++

    if c.Received == nClients {
        messages := make([]string, nClients)
        for i := 0; i < nClients; i++ {
            messages[i] = string(c.ExchangeData[i].Bytes())
        }
        return messages
    }
    return nil
}

func ImportJSON(path string, target interface{}) {
    // read file into string
    file, err := ioutil.ReadFile(path)
    if err != nil {
        fmt.Printf("Error reading file: %v\n", err)
        os.Exit(1)
    }
    
    // parse JSON into target struct
    err = json.Unmarshal(file, target)
    if err != nil {
        fmt.Printf("Error unmarshaling JSON: %v\n", err)
        os.Exit(1)
    }
}

func main() {
    P, _ := new(big.Int).SetString(p, 10)
    //G, _ := new(big.Int).SetString(q, 10)

	// read public key data
	nClients := 8
    var publicData PublicData
    ImportJSON("./keys/client.json", &publicData)
    publicData.PublicKeys = publicData.PublicKeys[:nClients]

	// read private key data for all clients
	clients := make([]Client, nClients)
	for i := 0; i < nClients; i++ {
		ImportJSON(fmt.Sprintf("./keys/client-%d.json", i), &clients[i].ClientData)
        clients[i].PublicData = publicData
        clients[i].ComputeSecrets(publicData.PublicKeys, P)
    }

    // do a single dc-net exchange locally
    for i := 0; i < nClients; i++ {
        text := fmt.Sprintf("This is client-%d's message.", i)
        transmission := clients[i].PrepareExchange(0, text)
        messages := clients[0].HandleExchange(0, i, transmission)
        if messages != nil {
            for j := 0; j < nClients; j++ {
                fmt.Printf("%v\n", messages[j])
            }
        }
    }
}
