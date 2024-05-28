package vm

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

// Gas table
func MemoryGasCost(mem *Memory, wordSize uint64) (uint64, error) {
	return memoryGasCost(mem, wordSize)
}

// Stack
func NewStack() *Stack {
	return newstack()
}

func (st *Stack) Len() int {
	return st.len()
}

func (st *Stack) Push(d *uint256.Int) {
	st.push(d)
}

// EVM
func (evm *EVM) GetDepth() int {
	return evm.depth
}

func (evm *EVM) SetDepth(depth int) {
	evm.depth = depth
}

// CallContext Call interceptor
// CallContextInterceptor provides a basic interface for the EVM calling conventions. The EVM
// depends on this context being implemented for doing subcalls and initialising new EVM contracts.
// Based on ethereum's CallContext Interface
type CallContextInterceptor interface {
	// Call calls another contract.
	Call(env *EVM, me ContractRef, addr common.Address, data []byte, gas uint64, value *uint256.Int) ([]byte, uint64, error)
	// CallCode takes another contracts code and execute within our own context
	CallCode(env *EVM, me ContractRef, addr common.Address, data []byte, gas uint64, value *uint256.Int) ([]byte, uint64, error)
	// DelegateCall is same as CallCode except sender and value is propagated from parent to child scope
	DelegateCall(env *EVM, me ContractRef, addr common.Address, data []byte, gas uint64) ([]byte, uint64, error)
	// Create creates a new contract
	Create(env *EVM, me ContractRef, data []byte, gas uint64, value *uint256.Int) ([]byte, common.Address, uint64, error)
	// Create2 creates a new contract with a deterministic address
	Create2(env *EVM, me ContractRef, code []byte, gas uint64, value *uint256.Int, salt *uint256.Int) ([]byte, common.Address, uint64, error)
	// StaticCall executes a contract in read-only mode
	StaticCall(env *EVM, me ContractRef, addr common.Address, input []byte, gas uint64) ([]byte, uint64, error)
}

// -- Interpreter Implementation Registry --

// Interpreter defines an interface for different interpreter implementations.
type Interpreter interface {
	// Run the contract's code with the given input data and returns the return byte-slice
	// and an error if one occurred.
	Run(contract *Contract, input []byte, readOnly bool) (ret []byte, err error)
}

type InterpreterFactory func(evm *EVM, cfg Config) Interpreter

var interpreter_registry = map[string]InterpreterFactory{}

func RegisterInterpreterFactory(name string, factory InterpreterFactory) {
	interpreter_registry[strings.ToLower(name)] = factory
}

func NewInterpreter(name string, evm *EVM, cfg Config) Interpreter {
	factory, found := interpreter_registry[strings.ToLower(name)]
	if !found {
		panic(fmt.Sprintf("no factory for interpreter %s registered", name))
	}
	return factory(evm, cfg)
}

func init() {
	factory := func(evm *EVM, cfg Config) Interpreter {
		return NewEVMInterpreter(evm)
	}
	RegisterInterpreterFactory("", factory)
	RegisterInterpreterFactory("geth", factory)
}

// --- Abstracted interpreter with step execution ---

type Status int

const (
	Running Status = iota
	Reverted
	Stopped
	Failed
)

// InterpreterState is a snapshot of the EVM state that can be used to test the effects of
// running single operations.
type InterpreterState struct {
	Contract           *Contract
	Status             Status
	Input              []byte
	ReadOnly           bool
	Stack              *Stack
	Memory             *Memory
	Pc                 uint64
	Error              error
	LastCallReturnData []byte
	ReturnData         []byte
}

func (in *EVMInterpreter) Step(state *InterpreterState) {
	// run a single operation
	res, err := in.run(state, 1)
	if errors.Is(err, ErrExecutionReverted) {
		state.Status = Reverted
		state.ReturnData = res
	} else if errors.Is(state.Error, errStopToken) {
		state.Status = Stopped
		state.ReturnData = res
	} else if err != nil {
		state.Status = Failed
	} else {
		state.Status = Running
	}

	// extract internal interpreter state
	state.LastCallReturnData = in.returnData
}
