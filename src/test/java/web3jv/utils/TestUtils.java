package web3jv.utils;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TestUtils {

    @DisplayName("18자리 wei를 ether로 변환시 0.x...가 된다")
    @Test
    public void fromWeiToEtherLength18Test() {
        String result = Utils.fromWeiString("545109094442210255", () -> 18);

        assertEquals("0.545109094442210255", result);
    }

    @DisplayName("16자리 wei를 ether로 변환시 0.00x...가 된다")
    @Test
    public void fromWeiToEtherLengthUnder18Test() {
        String result = Utils.fromWeiString("5451090944422102", EtherUnit.ETHER);

        assertEquals("0.005451090944422102", result);
    }

    @DisplayName("20자리 wei를 ether로 변환 시 xx.x...로 된다")
    @Test
    public void fromWeiToEtherLengthOver18Test() {
        String result = Utils.fromWeiString("50010909444221025577", EtherUnit.ETHER);

        assertEquals("50.010909444221025577", result);
    }

    @DisplayName("wei를 Gwei로 변환된다")
    @Test
    public void fromWeiToGewiTest() {
        String result = Utils.fromWeiString("545109094442210255", EtherUnit.GWEI);

        assertEquals("545109094.442210255", result);
    }

    @DisplayName("Ether단위가 wei단위로 변환된다")
    @Test
    public void toWeiFromEtherTest() {
        String result = Utils.toWeiString("0.545109094442210255", EtherUnit.ETHER);
        String result2 = Utils.toWeiString("0.005451090944422102", EtherUnit.ETHER);
        String result3 = Utils.toWeiString("50.010909444221025577", EtherUnit.ETHER);
        String result4 = Utils.toWeiString("52.01090", EtherUnit.ETHER);
        String result5 = Utils.toWeiString("24", EtherUnit.ETHER);

        assertEquals("545109094442210255", result);
        assertEquals("5451090944422102", result2);
        assertEquals("50010909444221025577", result3);
        assertEquals("52010900000000000000", result4);
        assertEquals("24000000000000000000", result5);
    }

    @DisplayName("Gwei단위가 wei단위로 변환된다")
    @Test
    public void toWeiFromMicroetherTest() {
        String result = Utils.toWeiString("0.545109094442210255", EtherUnit.GWEI);
        String result2 = Utils.toWeiString("35666", EtherUnit.GWEI);

        assertEquals("545109094.442210255", result);
        assertEquals("35666000000000", result2);
    }
}
