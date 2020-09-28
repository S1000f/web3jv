package web3jv.jsonrpc.abi;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import web3jv.utils.EtherUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Erc20Test {

    private String addressFrom;
    private String addressTo;

    @BeforeEach
    public void setUp() {
        addressFrom = "0x4038Aa65Ab984C1816C0e27C54Da14AC21E93643";
        addressTo = "0xa11CB28A6066684DB968075101031d3151dC40ED";
    }

    @DisplayName("ERC20 balanceOf ABI 를 위한 트랜젝션 데이터 값이 헥스스트링으로 반환된다")
    @Test
    public void erc20BalanceOfTest() {
        ERC20 erc20 = new ERC20();
        String txData = erc20.getTxDataBalanceOf(addressFrom);

        assertEquals("0x70a082310000000000000000000000004038aa65ab984c1816c0e27c54da14ac21e93643", txData);
    }

    @DisplayName("ERC20 transfer 의 txData 값이 헥스스트링으로 반한된다")
    @Test
    public void erc20TransferTest() {
        ERC20 erc20 = new ERC20();
        String txData = erc20.getTxDataTransfer(addressTo, "1000", EtherUnit.ETHER);

        assertEquals("0xa9059cbb000000000000000000000000a11cb28a6066684db968075101031d3151dc40ed" +
                "00000000000000000000000000000000000000000000003635c9adc5dea00000", txData);

    }

}
