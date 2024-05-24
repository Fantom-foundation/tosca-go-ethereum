package vm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInterpreterFactory(t *testing.T) {
	evm := &EVM{}
	cfg := Config{}

	interpreter := NewInterpreter("", evm, cfg)
	if interpreter == nil {
		t.Error("Expected interpreter to be created, but got nil")
	}
	interpreter = NewInterpreter("geth", evm, cfg)
	if interpreter == nil {
		t.Error("Expected interpreter to be created, but got nil")
	}
	asserted := assert.Panics(t, func() { NewInterpreter("invalid", evm, cfg) })
	if !asserted {
		t.Error("Expected panic with invalid interpreter name")
	}
}

func TestInterpreterFactory_RegisterInterpreter(t *testing.T) {
	evm := &EVM{}
	cfg := Config{}
	correctFactoryIsCalled := false

	RegisterInterpreterFactory("newInterpreter", func(evm *EVM, cfg Config) Interpreter {
		correctFactoryIsCalled = true
		return NewEVMInterpreter(evm)
	})

	interpreter := NewInterpreter("newInterpreter", evm, cfg)
	if interpreter == nil {
		t.Error("Expected interpreter to be created, but got nil")
	}
	if !correctFactoryIsCalled {
		t.Error("Wrong interpreter factory has been called")
	}
}
