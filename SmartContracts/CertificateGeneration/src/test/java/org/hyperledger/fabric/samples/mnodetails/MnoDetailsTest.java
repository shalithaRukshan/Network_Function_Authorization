package org.hyperledger.fabric.samples.mnodetails;

import org.hyperledger.fabric.contract.Context;
import org.hyperledger.fabric.shim.ChaincodeException;
import org.hyperledger.fabric.shim.ChaincodeStub;
import org.hyperledger.fabric.shim.ledger.KeyValue;
import org.hyperledger.fabric.shim.ledger.QueryResultsIterator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.ThrowableAssert.catchThrowable;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
//import static org.mockito.Mockito.verifyZeroInteractions;

public class MnoDetailsTest {

//    private final class MockKeyValue implements KeyValue {
//
//        private final String key;
//        private final String value;
//
//        MockKeyValue(final String key, final String value) {
//            super();
//            this.key = key;
//            this.value = value;
//        }
//
//        @Override
//        public String getKey() {
//            return this.key;
//        }
//
//        @Override
//        public String getStringValue() {
//            return this.value;
//        }
//
//        @Override
//        public byte[] getValue() {
//            return this.value.getBytes();
//        }
//
//    }
//
//    private final class MockMnoResultsIterator implements QueryResultsIterator<KeyValue> {
//
//        private final List<KeyValue> mnoList;
//
//        MockMnoResultsIterator() {
//            super();
//
//            mnoList = new ArrayList<KeyValue>();
//
//            mnoList.add(new MnoDetailsTest.MockKeyValue("mno1",
//                    "{ \"mnoId\": \"mno1\", \"mnoName\": \"mno1\", \"endpoint\": \"http://localhost:9000/api/mno\"}"));
//            mnoList.add(new MnoDetailsTest.MockKeyValue("mno2",
//                    "{ \"mnoId\": \"mno2\", \"mnoName\": \"mno2\", \"endpoint\": \"http://localhost:9000/api/mno\"}"));
//            mnoList.add(new MnoDetailsTest.MockKeyValue("mno3",
//                    "{ \"mnoId\": \"mno3\", \"mnoName\": \"mno3\", \"endpoint\": \"http://localhost:9000/api/mno\"}"));
//            mnoList.add(new MnoDetailsTest.MockKeyValue("mno4",
//                    "{ \"mnoId\": \"mno4\", \"mnoName\": \"mno4\", \"endpoint\": \"http://localhost:9000/api/mno\"}"));
//            mnoList.add(new MnoDetailsTest.MockKeyValue("mno5",
//                    "{ \"mnoId\": \"mno5\", \"mnoName\": \"mno5\", \"endpoint\": \"http://localhost:9000/api/mno\"}"));
//            mnoList.add(new MnoDetailsTest.MockKeyValue("mno6",
//                    "{ \"mnoId\": \"mno6\", \"mnoName\": \"mno6\", \"endpoint\": \"http://localhost:9000/api/mno\"}"));
//
//        }
//
//        @Override
//        public Iterator<KeyValue> iterator() {
//            return mnoList.iterator();
//        }
//
//        @Override
//        public void close() throws Exception {
//            // do nothing
//        }
//
//    }
//
//    @Test
//    public void invokeUnknownTransaction() {
//        MnoDetails contract = new MnoDetails();
//        Context ctx = mock(Context.class);
//
//        Throwable thrown = catchThrowable(() -> {
//            contract.unknownTransaction(ctx);
//        });
//
//        assertThat(thrown).isInstanceOf(ChaincodeException.class).hasNoCause()
//                .hasMessage("Undefined contract method called");
//        assertThat(((ChaincodeException) thrown).getPayload()).isEqualTo(null);
//
//        verifyZeroInteractions(ctx);
//    }
//
//    @Nested
//    class InvokeReadAssetTransaction {
//
//        @Test
//        public void whenMnoExists() {
//            MnoDetails contract = new MnoDetails();
//            Context ctx = mock(Context.class);
//            ChaincodeStub stub = mock(ChaincodeStub.class);
//            when(ctx.getStub()).thenReturn(stub);
//            when(stub.getStringState("mno1"))
//                    .thenReturn("{ \"mnoId\": \"112313\", \"mnoName\": \"mno1\", \"endpoint\": \"http://localhost:9000/api/mno\"}");
//            Mno mno = contract.ReadMno(ctx, "mno1");
//
//            assertThat(mno).isEqualTo(new Mno("112313", "mno1", "http://localhost:9000/api/mno", publicKey));
//        }
//
//        @Test
//        public void WhenMnoDoesNotExist() {
//            MnoDetails contract = new MnoDetails();
//            Context ctx = mock(Context.class);
//            ChaincodeStub stub = mock(ChaincodeStub.class);
//            when(ctx.getStub()).thenReturn(stub);
//            when(stub.getStringState("mno1")).thenReturn("");
//
//            Throwable thrown = catchThrowable(() -> {
//                contract.ReadMno(ctx, "mno1");
//            });
//
//            assertThat(thrown).isInstanceOf(ChaincodeException.class).hasNoCause()
//                    .hasMessage("Mno mno1 does not exist");
//            assertThat(((ChaincodeException) thrown).getPayload()).isEqualTo("MNO_NOT_FOUND".getBytes());
//        }
//    }
//
//    @Test
//    void invokeInitLedgerTransaction() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
//        MnoDetails contract = new MnoDetails();
//        Context ctx = mock(Context.class);
//        ChaincodeStub stub = mock(ChaincodeStub.class);
//        when(ctx.getStub()).thenReturn(stub);
//
//        contract.InitLedger(ctx);
//
//        InOrder inOrder = inOrder(stub);
//        inOrder.verify(stub).putStringState("mno1", "{\"endpoint\":\"http://localhost:9000/api/mno\",\"mnoId\":\"mno1\",\"mnoName\":\"mno1\"}");
//        inOrder.verify(stub).putStringState("mno2", "{\"endpoint\":\"http://localhost:9000/api/mno\",\"mnoId\":\"mno2\",\"mnoName\":\"mno2\"}");
//        inOrder.verify(stub).putStringState("mno3", "{\"endpoint\":\"http://localhost:9000/api/mno\",\"mnoId\":\"mno3\",\"mnoName\":\"mno3\"}");
//        inOrder.verify(stub).putStringState("mno4", "{\"endpoint\":\"http://localhost:9000/api/mno\",\"mnoId\":\"mno4\",\"mnoName\":\"mno4\"}");
//        inOrder.verify(stub).putStringState("mno5", "{\"endpoint\":\"http://localhost:9000/api/mno\",\"mnoId\":\"mno5\",\"mnoName\":\"mno5\"}");
//
//    }
//
//    @Nested
//    class InvokeCreateAssetTransaction {
//
//        @Test
//        public void whenAssetExists() {
//            MnoDetails contract = new MnoDetails();
//            Context ctx = mock(Context.class);
//            ChaincodeStub stub = mock(ChaincodeStub.class);
//            when(ctx.getStub()).thenReturn(stub);
//            when(stub.getStringState("mno1"))
//                    .thenReturn("{\"mnoId\":\"mno1\",\"mnoName\":\"mno1\",\"endpoint\":\"http://localhost:9000/api/mno\"}");
//
//            Throwable thrown = catchThrowable(() -> {
//                contract.CreateMno(ctx, "mno1", "mno1", "http://localhost:9000/api/mno");
//            });
//
//            assertThat(thrown).isInstanceOf(ChaincodeException.class).hasNoCause()
//                    .hasMessage("Mno mno1 already exists");
//            assertThat(((ChaincodeException) thrown).getPayload()).isEqualTo("MNO_ALREADY_EXIST".getBytes());
//        }
//
//        @Test
//        public void WhenMnoDoesNotExist() {
//            MnoDetails contract = new MnoDetails();
//            Context ctx = mock(Context.class);
//            ChaincodeStub stub = mock(ChaincodeStub.class);
//            when(ctx.getStub()).thenReturn(stub);
//            when(stub.getStringState("mno1")).thenReturn("");
//
//            Mno mno = contract.CreateMno(ctx, "mno1", "mno1", "http://localhost:9000/api/mno");
//
//            assertThat(mno).isEqualTo(new Mno("mno1", "mno1", "http://localhost:9000/api/mno", publicKey));
//        }
//    }

//    @Test
//    void invokeGetAllAssetsTransaction() {
//        MnoDetails contract = new MnoDetails();
//        Context ctx = mock(Context.class);
//        ChaincodeStub stub = mock(ChaincodeStub.class);
//        when(ctx.getStub()).thenReturn(stub);
//        when(stub.getStateByRange("", "")).thenReturn(new MnoDetailsTest.MockMnoResultsIterator());
//
//        String assets = contract.GetAllMNOs(ctx);
//
//        assertThat(assets).isEqualTo("[{\"endpoint\":\"http://localhost:9000/api/mno\",\"mnoId\":\"mno1\",\"mnoName\":\"mno1\"},"
//                + "{\"endpoint\":\"http://localhost:9000/api/mno\",\"mnoId\":\"mno2\",\"mnoName\":\"mno2\"},"
//                + "{\"endpoint\":\"http://localhost:9000/api/mno\",\"mnoId\":\"mno3\",\"mnoName\":\"mno3\"},"
//                + "{\"endpoint\":\"http://localhost:9000/api/mno\",\"mnoId\":\"mno4\",\"mnoName\":\"mno4\"},"
//                + "{\"endpoint\":\"http://localhost:9000/api/mno\",\"mnoId\":\"mno5\",\"mnoName\":\"mno5\"},"
//                + "{\"endpoint\":\"http://localhost:9000/api/mno\",\"mnoId\":\"mno6\",\"mnoName\":\"mno6\"}]");
//
//    }

//    @Nested
//    class TransferAssetTransaction {
//
//        @Test
//        public void whenAssetExists() {
//            AssetTransfer contract = new AssetTransfer();
//            Context ctx = mock(Context.class);
//            ChaincodeStub stub = mock(ChaincodeStub.class);
//            when(ctx.getStub()).thenReturn(stub);
//            when(stub.getStringState("asset1"))
//                    .thenReturn("{ \"assetID\": \"asset1\", \"color\": \"blue\", \"size\": 5, \"owner\": \"Tomoko\", \"appraisedValue\": 300 }");
//
//            String oldOwner = contract.TransferAsset(ctx, "asset1", "Dr Evil");
//
//            assertThat(oldOwner).isEqualTo("Tomoko");
//        }
//
//        @Test
//        public void whenAssetDoesNotExist() {
//            AssetTransfer contract = new AssetTransfer();
//            Context ctx = mock(Context.class);
//            ChaincodeStub stub = mock(ChaincodeStub.class);
//            when(ctx.getStub()).thenReturn(stub);
//            when(stub.getStringState("asset1")).thenReturn("");
//
//            Throwable thrown = catchThrowable(() -> {
//                contract.TransferAsset(ctx, "asset1", "Dr Evil");
//            });
//
//            assertThat(thrown).isInstanceOf(ChaincodeException.class).hasNoCause()
//                    .hasMessage("Asset asset1 does not exist");
//            assertThat(((ChaincodeException) thrown).getPayload()).isEqualTo("ASSET_NOT_FOUND".getBytes());
//        }
//    }

//    @Nested
//    class UpdateMnoTransaction {
//
//        @Test
//        public void whenMnoExists() {
//            MnoDetails contract = new MnoDetails();
//            Context ctx = mock(Context.class);
//            ChaincodeStub stub = mock(ChaincodeStub.class);
//            when(ctx.getStub()).thenReturn(stub);
//            when(stub.getStringState("mno1"))
//                    .thenReturn("{ \"mnoId\": \"mno1\", \"mnoName\": \"mno1\", \"endpoint\": \"http://localhost:9000/api/mno\"}");
//
//            Mno mno = contract.UpdateMno(ctx, "mno1", "mno1", "http://localhost:9000/api/mno",);
//
//            assertThat(mno).isEqualTo(new Mno("mno1", "mno1", "http://localhost:9000/api/mno", publicKey));
//        }

//        @Test
//        public void whenMnoDoesNotExist() {
//            MnoDetails contract = new MnoDetails();
//            Context ctx = mock(Context.class);
//            ChaincodeStub stub = mock(ChaincodeStub.class);
//            when(ctx.getStub()).thenReturn(stub);
//            when(stub.getStringState("mno1")).thenReturn("");
//
////            Throwable thrown = catchThrowable(() -> {
////                contract.Tra(ctx, "mno1", "mno1");
////            });
//
//            assertThat(thrown).isInstanceOf(ChaincodeException.class).hasNoCause()
//                    .hasMessage("Asset asset1 does not exist");
//            assertThat(((ChaincodeException) thrown).getPayload()).isEqualTo("ASSET_NOT_FOUND".getBytes());
//        }
    }

//    @Nested
//    class DeleteMnoTransaction {
//
//        @Test
//        public void whenAssetDoesNotExist() {
//            MnoDetails contract = new MnoDetails();
//            Context ctx = mock(Context.class);
//            ChaincodeStub stub = mock(ChaincodeStub.class);
//            when(ctx.getStub()).thenReturn(stub);
//            when(stub.getStringState("asset1")).thenReturn("");
//
//            Throwable thrown = catchThrowable(() -> {
//                contract.DeleteMno(ctx, "mno1");
//            });
//
//            assertThat(thrown).isInstanceOf(ChaincodeException.class).hasNoCause()
//                    .hasMessage("Mno mno1 does not exist");
//            assertThat(((ChaincodeException) thrown).getPayload()).isEqualTo("MNO_NOT_FOUND".getBytes());
//        }
//    }
//}
