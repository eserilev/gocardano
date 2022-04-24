package address

const (
	// Payment key hash only
	KEY_NONE AddressType = 0b0110
)

type AddressType int

type Address struct {
	/* A shelley address. It consists of two parts: payment part and staking part.
	       Either of the parts could be None, but they cannot be None at the same time.
	   Args:
	       payment_part (Union[VerificationKeyHash, ScriptHash, None]): Payment part of the address.
	       staking_part (Union[KeyHash, ScriptHash, PointerAddress, None]): Staking part of the address.
	       network (Network): Type of network the address belongs to.
	*/
	VerificationKeyHash []byte
	Network             string
}

func (a *Address) GetAddressType(key VerificationKey) {

}
