package org.swasthyasetu.bluetooth;

import android.Manifest;
import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattServer;
import android.bluetooth.BluetoothGattServerCallback;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.le.AdvertiseCallback;
import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertiseSettings;
import android.bluetooth.le.BluetoothLeAdvertiser;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelUuid;
import android.util.Base64;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import androidx.webkit.WebViewAssetLoader;
import androidx.webkit.WebViewCompat;
import androidx.webkit.WebViewFeature;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class MainActivity extends Activity {
    private static final String ASSET_URL =
            "https://appassets.androidplatform.net/assets/swasthyasetu-v5.html";
    private static final String ASSET_HOST = "appassets.androidplatform.net";
    private WebView webView;
    private WebViewAssetLoader assetLoader;
    private BleTransfer ble;

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        webView = new WebView(this);
        webView.setBackgroundColor(android.graphics.Color.WHITE);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setAllowFileAccessFromFileURLs(false);
        settings.setAllowUniversalAccessFromFileURLs(false);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        settings.setSafeBrowsingEnabled(true);

        assetLoader = new WebViewAssetLoader.Builder()
                .addPathHandler("/assets/", new WebViewAssetLoader.AssetsPathHandler(this))
                .build();
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                return assetLoader.shouldInterceptRequest(request.getUrl());
            }

            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                if (isAppPage(uri)) {
                    return false;
                }
                if ("https".equals(uri.getScheme()) && request.isForMainFrame()) {
                    try {
                        startActivity(new Intent(Intent.ACTION_VIEW, uri));
                    } catch (Exception ignored) {
                        postStatus("Could not open that secure link.");
                    }
                }
                return true;
            }
        });
        setContentView(webView);
        ble = new BleTransfer(this);
        if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            WebViewCompat.addWebMessageListener(
                    webView,
                    "AndroidBluetooth",
                    Collections.singleton("https://" + ASSET_HOST),
                    (view, message, sourceOrigin, isMainFrame, replyProxy) -> {
                        if (!isMainFrame || !isTrustedOrigin(sourceOrigin) || !isAppPage(view.getUrl())) {
                            return;
                        }
                        String data = message.getData();
                        runOnUiThread(() -> handleBridgeMessage(data));
                    });
        }
        webView.loadUrl(ASSET_URL);
    }

    private boolean isTrustedOrigin(Uri uri) {
        return uri != null
                && "https".equals(uri.getScheme())
                && ASSET_HOST.equals(uri.getHost())
                && (uri.getPath() == null || uri.getPath().isEmpty() || "/".equals(uri.getPath()));
    }

    private boolean isAppPage(Uri uri) {
        return uri != null
                && "https".equals(uri.getScheme())
                && ASSET_HOST.equals(uri.getHost())
                && "/assets/swasthyasetu-v5.html".equals(uri.getPath());
    }

    private boolean isAppPage(String url) {
        try {
            return isAppPage(Uri.parse(url));
        } catch (Exception ignored) {
            return false;
        }
    }

    private void handleBridgeMessage(String raw) {
        if (!isAppPage(webView.getUrl())) {
            return;
        }
        try {
            JSONObject message = new JSONObject(raw);
            String action = message.optString("action");
            switch (action) {
                case "ready":
                    if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
                        postStatus("This Android System WebView is too old for the secure Bluetooth bridge. Update Android System WebView.");
                    } else {
                        postStatus("Bluetooth ready. Keep both app phones nearby; no case is sent until you select and confirm.");
                    }
                    break;
                case "scan":
                    ble.startScan();
                    break;
                case "receive":
                    ble.startReceiving();
                    break;
                case "send":
                    String address = message.optString("address");
                    JSONObject caseData = sanitizeCase(message.optJSONObject("caseData"));
                    if (address.isEmpty() || caseData == null) {
                        postStatus("The selected case is invalid or does not have patient sharing consent.");
                    } else {
                        ble.send(address, caseData);
                    }
                    break;
                case "discard":
                    ble.discardIncoming();
                    break;
                case "pairApprove":
                    ble.approvePairing();
                    break;
                case "pairReject":
                    ble.rejectPairing();
                    break;
                case "decrypt":
                    ble.decryptAndPreview();
                    break;
                default:
                    postStatus("Unknown Bluetooth action.");
            }
        } catch (JSONException e) {
            postStatus("Could not read the Bluetooth request.");
        }
    }

    private JSONObject sanitizeCase(JSONObject input) {
        if (input == null || !input.optBoolean("shareConsent", false)) {
            return null;
        }
        try {
            JSONObject out = new JSONObject();
            putBoundedString(out, input, "id", 100, true);
            putBoundedString(out, input, "name", 50, false);
            putBoundedString(out, input, "village", 80, false);
            putBoundedString(out, input, "notes", 400, false);
            int age = input.optInt("age", 0);
            if (age < 0 || age > 130) return null;
            out.put("age", age);
            double temp = input.optDouble("temp", 0);
            if (!Double.isFinite(temp) || temp < 0 || temp > 60) return null;
            out.put("temp", temp);
            out.put("sym", sanitizeStrings(input.optJSONArray("sym"), 16, 40));
            out.put("danger", sanitizeStrings(input.optJSONArray("danger"), 16, 40));
            out.put("why", sanitizeStrings(input.optJSONArray("why"), 16, 120));
            String triage = input.optString("triage", "");
            if (!Arrays.asList("red", "amber", "green").contains(triage)) return null;
            out.put("triage", triage);
            out.put("shareConsent", true);
            out.put("ts", Math.max(0, input.optLong("ts", System.currentTimeMillis())));
            if (out.toString().getBytes(StandardCharsets.UTF_8).length > BleTransfer.MAX_PLAINTEXT_BYTES) {
                return null;
            }
            return out;
        } catch (JSONException | IllegalArgumentException e) {
            return null;
        }
    }

    private void putBoundedString(JSONObject target, JSONObject source, String key, int limit, boolean required)
            throws JSONException {
        String value = source.optString(key, "");
        if (value.length() > limit || (required && value.isEmpty())) {
            throw new IllegalArgumentException("Invalid " + key);
        }
        target.put(key, value);
    }

    private JSONArray sanitizeStrings(JSONArray values, int maxCount, int maxLength) {
        JSONArray result = new JSONArray();
        if (values == null || values.length() > maxCount) {
            throw new IllegalArgumentException("Invalid list");
        }
        for (int i = 0; i < values.length(); i++) {
            String value = values.optString(i, "");
            if (value.isEmpty() || value.length() > maxLength) {
                throw new IllegalArgumentException("Invalid list item");
            }
            result.put(value);
        }
        return result;
    }

    private void postStatus(String message) {
    JSONObject event = new JSONObject();
    try {
        event.put("type", "status");
        event.put("message", message);
    } catch (JSONException ignored) {
    }
    postEvent(event);
    }

    private void postEvent(JSONObject event) {
        runOnUiThread(() -> {
            if (webView == null || !isAppPage(webView.getUrl())) return;
            webView.evaluateJavascript("window.btNativeEvent&&window.btNativeEvent(JSON.parse("
                    + JSONObject.quote(event.toString()) + "))", null);
        });
    }

    private void postIncoming(JSONObject payload) {
        JSONObject event = new JSONObject();
        try {
            event.put("type", "incoming");
            event.put("payload", payload);
        } catch (JSONException ignored) {
            postStatus("Received data could not be previewed and was discarded.");
            return;
        }
        postEvent(event);
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (ble != null) ble.onPermissionsResult(requestCode, grantResults);
    }

    @Override
    protected void onDestroy() {
        if (ble != null) ble.close();
        if (webView != null) {
            webView.destroy();
            webView = null;
        }
        super.onDestroy();
    }

    private static final class BleTransfer {
        private static final UUID SERVICE_UUID = UUID.fromString("61d3b980-1a2c-4e85-a9c2-72dd36b19210");
        private static final UUID CHARACTERISTIC_UUID = UUID.fromString("61d3b981-1a2c-4e85-a9c2-72dd36b19210");
        private static final UUID REPLY_UUID = UUID.fromString("61d3b982-1a2c-4e85-a9c2-72dd36b19210");
        private static final UUID CCCD_UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");
        private static final int REQUEST_PERMISSIONS = 10;
        private static final int MAX_PLAINTEXT_BYTES = 48 * 1024;
        private static final int MAX_MESSAGE_BYTES = 72 * 1024;
        private static final int HEADER_BYTES = 12;
        private static final int MAX_CHUNKS = 1024;
        private static final byte[] MAGIC = new byte[]{'S', 'S', 'B', '1'};
        private static final SecureRandom SECURE_RANDOM = new SecureRandom();
        private static final String CRYPTO_CONTEXT = "SwasthyaSetu BLE E2EE v1";

        private final MainActivity activity;
        private final Handler handler = new Handler(Looper.getMainLooper());
        private final BluetoothAdapter adapter;
        private final Map<String, BluetoothDevice> discovered = new LinkedHashMap<>();
        private BluetoothLeScanner scanner;
        private BluetoothLeAdvertiser advertiser;
        private BluetoothGattServer server;
        private BluetoothGatt centralGatt;
        private BluetoothGattCharacteristic serverWriteCharacteristic;
        private BluetoothGattCharacteristic serverReplyCharacteristic;
        private BluetoothGattCharacteristic centralWriteCharacteristic;
        private BluetoothGattCharacteristic centralReplyCharacteristic;
        private BluetoothGattDescriptor cccdDescriptor;
        private AdvertiseCallback advertiseCallback;
        private ScanCallback scanCallback;
        private Runnable scanTimeout;
        private Runnable transferTimeout;
        private byte[][] receivedChunks;
        private int expectedBytes;
        private int receivedCount;
        private int incomingChunkCount;
        private int receivedByteCount;
        private byte[][] centralChunks;
        private int centralExpectedBytes;
        private int centralReceivedCount;
        private int centralChunkCount;
        private int centralReceivedBytes;
        private int mtu = 23;
        private int serverMtu = 23;
        private byte[] outgoing;
        private List<byte[]> outgoingPackets;
        private int outgoingIndex;
        private final ArrayDeque<byte[]> serverNotifyQueue = new ArrayDeque<>();
        private boolean serverIndicationActive;
        private BluetoothDevice serverPeer;
        private KeyPair ephemeralKeyPair;
        private byte[] localNonce;
        private byte[] peerNonce;
        private byte[] encryptionKey;
        private byte[] confirmationKey;
        private byte[] transcriptHash;
        private byte[] pendingCiphertext;
        private byte[] pendingIv;
        private JSONObject senderCase;
        private String transferId;
        private String pairCode;
        private String outstandingRequest;
        private boolean senderRole;
        private boolean localPairApproved;
        private boolean peerPairApproved;
        private boolean secureReady;
        private boolean receiving;
        private String pendingOperation;
        private String pendingAddress;
        private JSONObject pendingCaseData;

        BleTransfer(MainActivity activity) {
            this.activity = activity;
            BluetoothManager manager = (BluetoothManager) activity.getSystemService(Context.BLUETOOTH_SERVICE);
            adapter = manager == null ? null : manager.getAdapter();
        }

        void startScan() {
            if (!beginWithPermissions("scan")) return;
            if (!usableAdapter()) return;
            stopScan();
            discovered.clear();
            scanner = adapter.getBluetoothLeScanner();
            if (scanner == null) {
                activity.postStatus("Bluetooth scanning is unavailable on this phone.");
                return;
            }
            scanCallback = new ScanCallback() {
                @Override
                public void onScanResult(int callbackType, ScanResult result) {
                    BluetoothDevice device = result.getDevice();
                    if (device == null || device.getAddress() == null) return;
                    discovered.put(device.getAddress(), device);
                    publishPeers();
                }

                @Override
                public void onScanFailed(int errorCode) {
                    activity.postStatus("Bluetooth scan failed (" + errorCode + "). Check Bluetooth permissions and try again.");
                }
            };
            try {
                ScanFilter filter = new ScanFilter.Builder()
                        .setServiceUuid(new ParcelUuid(SERVICE_UUID))
                        .build();
                ScanSettings settings = new ScanSettings.Builder()
                        .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                        .build();
                scanner.startScan(Collections.singletonList(filter), settings, scanCallback);
                activity.postStatus("Scanning for phones that tapped “Ready to receive”…");
                scanTimeout = () -> {
                    stopScan();
                    publishPeers();
                    activity.postStatus(discovered.isEmpty()
                            ? "No nearby recipient found. Ask the other phone to tap “Ready to receive”, keep phones nearby, and scan again."
                            : "Select the intended recipient below. Bluetooth range and walls may affect discovery.");
                };
                handler.postDelayed(scanTimeout, 20_000);
            } catch (SecurityException | IllegalStateException e) {
                activity.postStatus("Bluetooth scan could not start. Enable Bluetooth and grant the requested nearby-device/location permission.");
            }
        }

        private void publishPeers() {
            JSONArray peers = new JSONArray();
            for (Map.Entry<String, BluetoothDevice> entry : discovered.entrySet()) {
                JSONObject peer = new JSONObject();
                try {
                    peer.put("address", entry.getKey());
                    String name = "";
                    try {
                        name = entry.getValue().getName();
                    } catch (SecurityException ignored) {
                        // A nameless result can still be selected by the displayed device address.
                    }
                    peer.put("name", name == null || name.trim().isEmpty()
                            ? "Nearby phone (" + entry.getKey() + ")" : name);
                    peers.put(peer);
                } catch (JSONException ignored) {
                }
            }
            JSONObject event = new JSONObject();
            try {
                event.put("type", "peers");
                event.put("peers", peers);
            } catch (JSONException ignored) {
            }
            activity.postEvent(event);
        }

        void startReceiving() {
            if (!beginWithPermissions("receive")) return;
            if (!usableAdapter()) return;
            if (server != null) stopReceiving();
            clearCryptoState();
            senderRole = false;
            if (!adapter.isMultipleAdvertisementSupported()) {
                activity.postStatus("This phone does not support BLE peripheral advertising.");
                return;
            }
            try {
                server = ((BluetoothManager) activity.getSystemService(Context.BLUETOOTH_SERVICE))
                        .openGattServer(activity, serverCallback);
                if (server == null) {
                    activity.postStatus("Could not open the Bluetooth GATT server.");
                    return;
                }
                BluetoothGattService service = new BluetoothGattService(
                        SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY);
                serverWriteCharacteristic = new BluetoothGattCharacteristic(
                        CHARACTERISTIC_UUID,
                        BluetoothGattCharacteristic.PROPERTY_WRITE,
                        BluetoothGattCharacteristic.PERMISSION_WRITE);
                serverReplyCharacteristic = new BluetoothGattCharacteristic(
                        REPLY_UUID,
                        BluetoothGattCharacteristic.PROPERTY_INDICATE,
                        BluetoothGattCharacteristic.PERMISSION_READ);
                cccdDescriptor = new BluetoothGattDescriptor(
                        CCCD_UUID,
                        BluetoothGattDescriptor.PERMISSION_READ | BluetoothGattDescriptor.PERMISSION_WRITE);
                serverReplyCharacteristic.addDescriptor(cccdDescriptor);
                service.addCharacteristic(serverWriteCharacteristic);
                service.addCharacteristic(serverReplyCharacteristic);
                receiving = true;
                if (!server.addService(service)) {
                    stopReceiving();
                    activity.postStatus("Could not register the Bluetooth transfer service.");
                }
                activity.postStatus("Starting receive mode. Stay nearby; received data is not saved until you accept it.");
            } catch (SecurityException | IllegalStateException e) {
                stopReceiving();
                activity.postStatus("Could not start Bluetooth receive mode. Check permissions, Bluetooth state, and phone support.");
            }
        }

        private final BluetoothGattServerCallback serverCallback = new BluetoothGattServerCallback() {
            @Override
            public void onServiceAdded(int status, BluetoothGattService service) {
                if (status != BluetoothGatt.GATT_SUCCESS || !receiving) {
                    activity.postStatus("Could not add the BLE transfer service (" + status + ").");
                    stopReceiving();
                    return;
                }
                beginAdvertising();
            }

            @Override
            public void onConnectionStateChange(BluetoothDevice device, int status, int newState) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    activity.postStatus("The Bluetooth connection was interrupted. Check range and retry.");
                } else if (newState == BluetoothProfile.STATE_CONNECTED) {
                    if (serverPeer != null && !serverPeer.getAddress().equals(device.getAddress())) {
                        try {
                            server.cancelConnection(device);
                        } catch (SecurityException ignored) {
                        }
                        return;
                    }
                    serverPeer = device;
                    stopAdvertising();
                    activity.postStatus("A nearby phone connected. Waiting for its explicitly selected case.");
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    activity.postStatus("Sender disconnected. You can keep receive mode ready or stop it.");
                    if (serverPeer != null && serverPeer.getAddress().equals(device.getAddress())) {
                        serverPeer = null;
                        if (pendingCiphertext == null) clearCryptoState();
                    }
                }
            }

            @Override
            public void onMtuChanged(BluetoothDevice device, int mtu) {
                serverMtu = Math.max(23, mtu);
            }

            @Override
            public void onDescriptorWriteRequest(
                    BluetoothDevice device, int requestId, BluetoothGattDescriptor descriptor,
                    boolean preparedWrite, boolean responseNeeded, int offset, byte[] value) {
                int status = BluetoothGatt.GATT_SUCCESS;
                if (preparedWrite || offset != 0 || !CCCD_UUID.equals(descriptor.getUuid())
                        || !Arrays.equals(value, BluetoothGattDescriptor.ENABLE_INDICATION_VALUE)) {
                    status = BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED;
                } else {
                    serverPeer = device;
                    descriptor.setValue(value);
                }
                try {
                    if (responseNeeded && server != null) server.sendResponse(device, requestId, status, 0, null);
                } catch (SecurityException ignored) {
                    activity.postStatus("Could not enable the secure transfer response channel.");
                }
            }

            @Override
            public void onNotificationSent(BluetoothDevice device, int status) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    serverIndicationActive = false;
                    serverNotifyQueue.clear();
                    activity.postStatus("Secure Bluetooth response was interrupted. Check range and retry.");
                    return;
                }
                serverIndicationActive = false;
                sendNextServerIndication();
            }

            @Override
            public void onCharacteristicWriteRequest(
                    BluetoothDevice device, int requestId, BluetoothGattCharacteristic characteristic,
                    boolean preparedWrite, boolean responseNeeded, int offset, byte[] value) {
                int result = BluetoothGatt.GATT_SUCCESS;
                JSONObject request = null;
                if (!CHARACTERISTIC_UUID.equals(characteristic.getUuid()) || preparedWrite || offset != 0
                        || !responseNeeded || serverPeer == null
                        || !serverPeer.getAddress().equals(device.getAddress())) {
                    result = BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED;
                } else {
                    try {
                        request = receivePacket(value);
                        if (request == INVALID_PACKET) result = BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH;
                    } catch (Exception e) {
                        resetReceiveBuffer();
                        result = BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH;
                        activity.postStatus("Bluetooth frame was invalid or incomplete; no case was decrypted.");
                    }
                }
                try {
                    if (responseNeeded && server != null) {
                        server.sendResponse(device, requestId, result, 0, null);
                    }
                } catch (SecurityException ignored) {
                    activity.postStatus("Could not acknowledge received data. Check Bluetooth permissions.");
                }
                if (request != null && request != INVALID_PACKET) {
                    JSONObject response = handleSecureRequest(request);
                    if (response != null) sendServerMessage(response);
                }
            }
        };

        private static final JSONObject INVALID_PACKET = new JSONObject();

        private JSONObject receivePacket(byte[] packet) throws JSONException {
            if (packet == null || packet.length < HEADER_BYTES
                    || packet[0] != MAGIC[0] || packet[1] != MAGIC[1]
                    || packet[2] != MAGIC[2] || packet[3] != MAGIC[3]) {
                throw new IllegalArgumentException("Header");
            }
            ByteBuffer header = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN);
            header.position(4);
            int total = header.getInt();
            int index = Short.toUnsignedInt(header.getShort());
            int count = Short.toUnsignedInt(header.getShort());
            int bodyLength = packet.length - HEADER_BYTES;
            if (total < 1 || total > MAX_MESSAGE_BYTES || count < 1 || count > MAX_CHUNKS
                    || index >= count || bodyLength < 1) {
                throw new IllegalArgumentException("Bounds");
            }
            if (receivedChunks == null) {
                expectedBytes = total;
                incomingChunkCount = count;
                receivedChunks = new byte[count][];
                receivedCount = 0;
                transferTimeout = () -> {
                    resetReceiveBuffer();
                    activity.postStatus("Bluetooth transfer timed out. No incomplete data was saved.");
                };
                handler.postDelayed(transferTimeout, 90_000);
            }
            if (expectedBytes != total || incomingChunkCount != count || receivedChunks[index] != null) {
                throw new IllegalArgumentException("Sequence");
            }
            receivedChunks[index] = Arrays.copyOfRange(packet, HEADER_BYTES, packet.length);
            receivedByteCount += bodyLength;
            if (receivedByteCount > expectedBytes) throw new IllegalArgumentException("Too many bytes");
            receivedCount++;
            if (receivedCount != incomingChunkCount) return null;
            ByteArrayOutputStream assembled = new ByteArrayOutputStream(expectedBytes);
            for (byte[] chunk : receivedChunks) {
                if (chunk == null) throw new IllegalArgumentException("Missing chunk");
                assembled.write(chunk, 0, chunk.length);
            }
            byte[] bytes = assembled.toByteArray();
            if (bytes.length != expectedBytes) throw new IllegalArgumentException("Length mismatch");
            resetReceiveBuffer();
            return new JSONObject(new String(bytes, StandardCharsets.UTF_8));
        }

        private JSONObject handleSecureRequest(JSONObject request) {
            String type = request.optString("type", "");
            try {
                if ("hello".equals(type)) {
                    if (ephemeralKeyPair != null || pendingCiphertext != null
                            || request.optString("transferId", "").length() != 36) {
                        return errorMessage("A secure transfer session is already active.");
                    }
                    clearCryptoState();
                    senderRole = false;
                    transferId = request.optString("transferId");
                    byte[] senderPublic = Base64.decode(request.getString("publicKey"), Base64.DEFAULT);
                    byte[] senderNonce = Base64.decode(request.getString("nonce"), Base64.DEFAULT);
                    if (senderNonce.length != 32 || senderPublic.length > 256 || senderPublic.length < 32) {
                        return errorMessage("Invalid secure handshake.");
                    }
                    ephemeralKeyPair = newEphemeralKeyPair();
                    localNonce = randomBytes(32);
                    peerNonce = senderNonce;
                    deriveSessionKeys(senderPublic, ephemeralKeyPair.getPublic().getEncoded(), senderNonce, localNonce);
                    transferTimeout = () -> {
                        clearCryptoState();
                        activity.postStatus("Secure pairing timed out. No case was decrypted or saved.");
                    };
                    handler.postDelayed(transferTimeout, 90_000L);
                    JSONObject reply = new JSONObject();
                    reply.put("type", "hello_ack");
                    reply.put("transferId", transferId);
                    reply.put("publicKey", Base64.encodeToString(ephemeralKeyPair.getPublic().getEncoded(), Base64.NO_WRAP));
                    reply.put("nonce", Base64.encodeToString(localNonce, Base64.NO_WRAP));
                    showPairingCode("receiver");
                    return reply;
                }
                if ("pair_confirm".equals(type)) {
                    if (senderRole || confirmationKey == null || !"sender".equals(request.optString("role"))) {
                        return errorMessage("Secure pairing is not active.");
                    }
                    byte[] supplied = Base64.decode(request.optString("proof", ""), Base64.DEFAULT);
                    if (!MessageDigest.isEqual(supplied, confirmationProof("sender"))) {
                        rejectSession("Secure pairing verification failed.");
                        return errorMessage("Secure pairing verification failed.");
                    }
                    peerPairApproved = true;
                    JSONObject reply = new JSONObject();
                    if (localPairApproved) {
                        secureReady = true;
                        reply.put("type", "paired");
                        reply.put("proof", Base64.encodeToString(confirmationProof("receiver"), Base64.NO_WRAP));
                        postPaired("receiver");
                    } else {
                        reply.put("type", "waiting");
                        activity.postStatus("The other phone approved its code. Compare and approve the matching code here to continue.");
                    }
                    return reply;
                }
                if ("case".equals(type)) {
                    if (!secureReady || !peerPairApproved || !localPairApproved || pendingCiphertext != null) {
                        return errorMessage("Encrypted data arrived before both users verified the code.");
                    }
                    if (!transferId.equals(request.optString("transferId"))) {
                        return errorMessage("Encrypted transfer session did not match.");
                    }
                    byte[] iv = Base64.decode(request.optString("nonce", ""), Base64.DEFAULT);
                    byte[] ciphertext = Base64.decode(request.optString("ciphertext", ""), Base64.DEFAULT);
                    if (iv.length != 12 || ciphertext.length < 16
                            || ciphertext.length > MAX_PLAINTEXT_BYTES + 16) {
                        return errorMessage("Encrypted transfer size or nonce was invalid.");
                    }
                    pendingIv = iv;
                    pendingCiphertext = ciphertext;
                    postEncryptedReady(ciphertext.length);
                    transferTimeout = () -> {
                        if (pendingCiphertext != null) {
                            clearCryptoState();
                            activity.postStatus("Encrypted case expired before receiver consented to decrypt; temporary data was discarded.");
                        }
                    };
                    handler.postDelayed(transferTimeout, 5 * 60_000L);
                    JSONObject reply = new JSONObject();
                    reply.put("type", "stored");
                    return reply;
                }
                if ("cancel".equals(type)) {
                    rejectSession("The other phone cancelled secure pairing.");
                    return errorMessage("Transfer cancelled.");
                }
                return errorMessage("Unsupported secure transfer message.");
            } catch (Exception e) {
                rejectSession("Secure Bluetooth handshake or message validation failed. No case was imported.");
                return errorMessage("Secure transfer validation failed.");
            }
        }

        private JSONObject errorMessage(String message) {
            JSONObject response = new JSONObject();
            try {
                response.put("type", "error");
                response.put("message", message);
            } catch (JSONException ignored) {
            }
            return response;
        }

        private void showPairingCode(String role) {
            JSONObject event = new JSONObject();
            try {
                event.put("type", "pairing");
                event.put("role", role);
                event.put("code", pairCode);
            } catch (JSONException ignored) {
            }
            activity.postEvent(event);
            activity.postStatus("Compare the six-digit code in person on both phones. Do not approve unless the codes match exactly.");
        }

        private void postPaired(String role) {
            JSONObject event = new JSONObject();
            try {
                event.put("type", "paired");
                event.put("role", role);
            } catch (JSONException ignored) {
            }
            activity.postEvent(event);
        }

        private void postEncryptedReady(int ciphertextSize) {
            JSONObject event = new JSONObject();
            try {
                event.put("type", "encryptedReady");
                event.put("bytes", ciphertextSize);
            } catch (JSONException ignored) {
            }
            activity.postEvent(event);
        }

        private void sendServerMessage(JSONObject message) {
            try {
                byte[] bytes = message.toString().getBytes(StandardCharsets.UTF_8);
                List<byte[]> frames = packetize(bytes, serverMtu);
                if (frames == null) {
                    serverNotifyQueue.clear();
                    activity.postStatus("Bluetooth MTU is too small to safely return a secure response.");
                    return;
                }
                serverNotifyQueue.addAll(frames);
                sendNextServerIndication();
            } catch (RuntimeException e) {
                activity.postStatus("Could not prepare the secure Bluetooth response.");
            }
        }

        private void sendNextServerIndication() {
            if (serverIndicationActive || serverNotifyQueue.isEmpty() || serverPeer == null
                    || server == null || serverReplyCharacteristic == null) return;
            byte[] frame = serverNotifyQueue.peek();
            try {
                boolean started;
                if (Build.VERSION.SDK_INT >= 33) {
                    started = server.notifyCharacteristicChanged(serverPeer, serverReplyCharacteristic, true, frame)
                            == BluetoothGatt.GATT_SUCCESS;
                } else {
                    serverReplyCharacteristic.setValue(frame);
                    started = server.notifyCharacteristicChanged(serverPeer, serverReplyCharacteristic, true);
                }
                if (!started) {
                    serverNotifyQueue.clear();
                    activity.postStatus("Could not send a secure Bluetooth response. Check range and try again.");
                    return;
                }
                serverNotifyQueue.remove();
                serverIndicationActive = true;
            } catch (SecurityException e) {
                serverNotifyQueue.clear();
                activity.postStatus("Bluetooth permission was revoked while responding.");
            }
        }

        private List<byte[]> packetize(byte[] bytes, int negotiatedMtu) {
            if (bytes == null || bytes.length < 1 || bytes.length > MAX_MESSAGE_BYTES) return null;
            int bodySize = negotiatedMtu - 3 - HEADER_BYTES;
            if (bodySize < 1) return null;
            int count = (bytes.length + bodySize - 1) / bodySize;
            if (count > MAX_CHUNKS || count > 65535) return null;
            List<byte[]> frames = new ArrayList<>(count);
            for (int index = 0; index < count; index++) {
                int start = index * bodySize;
                int end = Math.min(bytes.length, start + bodySize);
                ByteBuffer frame = ByteBuffer.allocate(HEADER_BYTES + end - start).order(ByteOrder.BIG_ENDIAN);
                frame.put(MAGIC);
                frame.putInt(bytes.length);
                frame.putShort((short) index);
                frame.putShort((short) count);
                frame.put(bytes, start, end - start);
                frames.add(frame.array());
            }
            return frames;
        }

        private JSONObject receiveServerFrame(byte[] packet) throws JSONException {
            if (packet == null || packet.length < HEADER_BYTES
                    || packet[0] != MAGIC[0] || packet[1] != MAGIC[1]
                    || packet[2] != MAGIC[2] || packet[3] != MAGIC[3]) {
                throw new IllegalArgumentException("Reply frame header");
            }
            ByteBuffer header = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN);
            header.position(4);
            int total = header.getInt();
            int index = Short.toUnsignedInt(header.getShort());
            int count = Short.toUnsignedInt(header.getShort());
            int size = packet.length - HEADER_BYTES;
            if (total < 1 || total > MAX_MESSAGE_BYTES || count < 1 || count > MAX_CHUNKS
                    || index >= count || size < 1) throw new IllegalArgumentException("Reply bounds");
            if (centralChunks == null) {
                centralExpectedBytes = total;
                centralChunkCount = count;
                centralChunks = new byte[count][];
            }
            if (centralExpectedBytes != total || centralChunkCount != count || centralChunks[index] != null) {
                throw new IllegalArgumentException("Reply sequence");
            }
            centralChunks[index] = Arrays.copyOfRange(packet, HEADER_BYTES, packet.length);
            centralReceivedBytes += size;
            if (centralReceivedBytes > total) throw new IllegalArgumentException("Reply overflow");
            centralReceivedCount++;
            if (centralReceivedCount != count) return null;
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(total);
            for (byte[] chunk : centralChunks) {
                if (chunk == null) throw new IllegalArgumentException("Reply missing chunk");
                bytes.write(chunk, 0, chunk.length);
            }
            byte[] assembled = bytes.toByteArray();
            clearCentralReceive();
            if (assembled.length != total) throw new IllegalArgumentException("Reply length");
            return new JSONObject(new String(assembled, StandardCharsets.UTF_8));
        }

        private void clearCentralReceive() {
            if (centralChunks != null) {
                for (byte[] chunk : centralChunks) if (chunk != null) Arrays.fill(chunk, (byte) 0);
            }
            centralChunks = null;
            centralExpectedBytes = 0;
            centralChunkCount = 0;
            centralReceivedCount = 0;
            centralReceivedBytes = 0;
        }

        private void beginSenderHandshake() {
            try {
                senderRole = true;
                localPairApproved = false;
                peerPairApproved = false;
                secureReady = false;
                outstandingRequest = null;
                transferId = UUID.randomUUID().toString();
                ephemeralKeyPair = newEphemeralKeyPair();
                localNonce = randomBytes(32);
                JSONObject hello = new JSONObject();
                hello.put("type", "hello");
                hello.put("transferId", transferId);
                hello.put("publicKey", Base64.encodeToString(ephemeralKeyPair.getPublic().getEncoded(), Base64.NO_WRAP));
                hello.put("nonce", Base64.encodeToString(localNonce, Base64.NO_WRAP));
                sendSecureRequest(hello);
            } catch (Exception e) {
                failTransfer("Could not create the ephemeral ECDH key agreement.");
            }
        }

        private void sendSecureRequest(JSONObject message) {
            try {
                if (centralGatt == null || centralWriteCharacteristic == null
                        || outstandingRequest != null || outgoingPackets != null) {
                    failTransfer("A secure Bluetooth request is already in progress or the link is not ready.");
                    return;
                }
                byte[] bytes = message.toString().getBytes(StandardCharsets.UTF_8);
                List<byte[]> packets = packetize(bytes, mtu);
                if (packets == null) {
                    failTransfer("The negotiated Bluetooth MTU is too small for the secure handshake or case. Retry with a larger-MTU device.");
                    return;
                }
                outstandingRequest = message.optString("type", "");
                outgoingPackets = packets;
                outgoingIndex = 0;
                if (Build.VERSION.SDK_INT >= 33) {
                    centralWriteCharacteristic.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
                } else {
                    centralWriteCharacteristic.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
                }
                writeNextPacket(centralGatt);
            } catch (SecurityException | IllegalStateException e) {
                failTransfer("Could not send the secure Bluetooth message.");
            }
        }

        private void handleServerReply(JSONObject reply) {
            String type = reply.optString("type", "");
            try {
                if ("hello_ack".equals(type) && senderRole && ephemeralKeyPair != null) {
                    if (!"hello".equals(outstandingRequest)) throw new IllegalArgumentException("Unexpected hello reply");
                    outstandingRequest = null;
                    if (!transferId.equals(reply.optString("transferId"))) throw new IllegalArgumentException("Session");
                    byte[] receiverPublic = Base64.decode(reply.getString("publicKey"), Base64.DEFAULT);
                    byte[] receiverNonce = Base64.decode(reply.getString("nonce"), Base64.DEFAULT);
                    if (receiverNonce.length != 32 || receiverPublic.length > 256 || receiverPublic.length < 32) {
                        throw new IllegalArgumentException("Handshake bounds");
                    }
                    peerNonce = receiverNonce;
                    deriveSessionKeys(ephemeralKeyPair.getPublic().getEncoded(), receiverPublic, localNonce, receiverNonce);
                    showPairingCode("sender");
                    return;
                }
                if ("waiting".equals(type)) {
                    if (!"pair_confirm".equals(outstandingRequest)) throw new IllegalArgumentException("Unexpected pairing wait");
                    outstandingRequest = null;
                    activity.postStatus("Your code is approved here. Waiting for the receiver to compare and approve its matching code.");
                    return;
                }
                if ("paired".equals(type) || "pair_ready".equals(type)) {
                    if (!senderRole || !localPairApproved) throw new IllegalArgumentException("Unapproved pairing");
                    if ("paired".equals(type) && !"pair_confirm".equals(outstandingRequest)) {
                        throw new IllegalArgumentException("Unexpected pairing response");
                    }
                    outstandingRequest = null;
                    byte[] proof = Base64.decode(reply.optString("proof", ""), Base64.DEFAULT);
                    if (!MessageDigest.isEqual(proof, confirmationProof("receiver"))) {
                        throw new IllegalArgumentException("Receiver confirmation proof");
                    }
                    peerPairApproved = true;
                    secureReady = true;
                    postPaired("sender");
                    encryptAndSendCase();
                    return;
                }
                if ("stored".equals(type) && senderRole) {
                    if (!"case".equals(outstandingRequest)) throw new IllegalArgumentException("Unexpected storage response");
                    outstandingRequest = null;
                    outgoing = null;
                    closeCentral();
                    clearCryptoState();
                    JSONObject event = new JSONObject();
                    event.put("type", "sent");
                    activity.postEvent(event);
                    return;
                }
                if ("pair_rejected".equals(type)) {
                    outstandingRequest = null;
                    rejectSession("The other phone cancelled secure pairing. No case was sent.");
                    return;
                }
                if ("error".equals(type)) {
                    outstandingRequest = null;
                    rejectSession(reply.optString("message", "Secure Bluetooth transfer was rejected."));
                    return;
                }
                throw new IllegalArgumentException("Unexpected secure response");
            } catch (Exception e) {
                failTransfer("Secure Bluetooth response was invalid. The transfer was cancelled.");
            }
        }

        private void encryptAndSendCase() {
            if (!secureReady || !senderCaseReady()) return;
            try {
                byte[] plaintext = senderCase.toString().getBytes(StandardCharsets.UTF_8);
                if (plaintext.length > MAX_PLAINTEXT_BYTES) {
                    failTransfer("This case exceeds the 48 KiB plaintext limit for Bluetooth.");
                    return;
                }
                byte[] iv = randomBytes(12);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptionKey, "AES"), new GCMParameterSpec(128, iv));
                cipher.updateAAD(transcriptHash);
                byte[] ciphertext = cipher.doFinal(plaintext);
                Arrays.fill(plaintext, (byte) 0);
                JSONObject message = new JSONObject();
                message.put("type", "case");
                message.put("transferId", transferId);
                message.put("nonce", Base64.encodeToString(iv, Base64.NO_WRAP));
                message.put("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP));
                sendSecureRequest(message);
                Arrays.fill(ciphertext, (byte) 0);
            } catch (Exception e) {
                failTransfer("Could not encrypt the consented case for Bluetooth.");
            }
        }

        private boolean senderCaseReady() {
            return senderRole && senderCase != null && localPairApproved && peerPairApproved;
        }

        private void deriveSessionKeys(byte[] senderPublic, byte[] receiverPublic, byte[] senderSalt, byte[] receiverSalt)
                throws Exception {
            PublicKeyHolder peer = new PublicKeyHolder(KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(senderRole ? receiverPublic : senderPublic)));
            KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
            agreement.init(ephemeralKeyPair.getPrivate());
            agreement.doPhase(peer.key, true);
            byte[] shared = agreement.generateSecret();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(CRYPTO_CONTEXT.getBytes(StandardCharsets.UTF_8));
            digest.update(transferId.getBytes(StandardCharsets.UTF_8));
            digest.update(senderSalt);
            digest.update(receiverSalt);
            digest.update(ByteBuffer.allocate(4).putInt(senderPublic.length).array());
            digest.update(senderPublic);
            digest.update(ByteBuffer.allocate(4).putInt(receiverPublic.length).array());
            digest.update(receiverPublic);
            transcriptHash = digest.digest();
            byte[] salt = MessageDigest.getInstance("SHA-256").digest(concat(senderSalt, receiverSalt));
            byte[] material = hkdf(shared, salt, concat(CRYPTO_CONTEXT.getBytes(StandardCharsets.UTF_8), transcriptHash), 64);
            Arrays.fill(shared, (byte) 0);
            encryptionKey = Arrays.copyOfRange(material, 0, 32);
            confirmationKey = Arrays.copyOfRange(material, 32, 64);
            Arrays.fill(material, (byte) 0);
            byte[] sas = hmac(confirmationKey, concat("short-auth-string".getBytes(StandardCharsets.UTF_8), transcriptHash));
            int number = ((sas[0] & 0xff) << 12 | (sas[1] & 0xff) << 4 | ((sas[2] & 0xf0) >>> 4)) % 1_000_000;
            pairCode = String.format(java.util.Locale.ROOT, "%06d", number);
            Arrays.fill(sas, (byte) 0);
        }

        private static final class PublicKeyHolder {
            final java.security.PublicKey key;
            PublicKeyHolder(java.security.PublicKey key) { this.key = key; }
        }

        private byte[] confirmationProof(String role) throws Exception {
            return hmac(confirmationKey,
                    concat(("confirm-" + role).getBytes(StandardCharsets.UTF_8), transcriptHash));
        }

        private void approvePairing() {
            if (confirmationKey == null || pairCode == null) {
                activity.postStatus("No secure pairing code is ready. Connect to the other phone first.");
                return;
            }
            localPairApproved = true;
            if (senderRole) {
                try {
                    JSONObject confirm = new JSONObject();
                    confirm.put("type", "pair_confirm");
                    confirm.put("role", "sender");
                    confirm.put("proof", Base64.encodeToString(confirmationProof("sender"), Base64.NO_WRAP));
                    sendSecureRequest(confirm);
                    activity.postStatus("Code approved on this phone. Waiting for the recipient to compare and approve the same code.");
                } catch (Exception e) {
                    failTransfer("Could not verify secure pairing.");
                }
            } else {
                activity.postStatus(peerPairApproved
                        ? "Both users compared and approved the matching code. Secure channel established."
                        : "Code approved on this phone. Waiting for the sender to approve the same code.");
                if (peerPairApproved) {
                    secureReady = true;
                    postPaired("receiver");
                    JSONObject paired = new JSONObject();
                    try {
                        paired.put("type", "pair_ready");
                        paired.put("proof", Base64.encodeToString(confirmationProof("receiver"), Base64.NO_WRAP));
                        sendServerMessage(paired);
                    } catch (Exception ignored) {
                    }
                }
            }
        }

        private void rejectPairing() {
            rejectSession("Secure pairing cancelled. No case was sent.");
            JSONObject event = new JSONObject();
            try {
                event.put("type", "pairRejected");
                activity.postEvent(event);
            } catch (JSONException ignored) {
            }
        }

        private void rejectSession(String status) {
            activity.postStatus(status);
            if (senderRole) {
                if (centralGatt != null) closeCentral();
            } else if (serverPeer != null) {
                try {
                    if (server != null) server.cancelConnection(serverPeer);
                } catch (SecurityException ignored) {
                }
            }
            clearCryptoState();
            resetReceiveBuffer();
            clearCentralReceive();
        }

        private void clearCryptoKeysOnly() {
            wipe(encryptionKey);
            wipe(confirmationKey);
            wipe(transcriptHash);
            encryptionKey = null;
            confirmationKey = null;
            transcriptHash = null;
            ephemeralKeyPair = null;
            wipe(localNonce);
            wipe(peerNonce);
            localNonce = null;
            peerNonce = null;
            pairCode = null;
        }

        private void clearCryptoState() {
            if (transferTimeout != null) handler.removeCallbacks(transferTimeout);
            transferTimeout = null;
            clearCryptoKeysOnly();
            wipe(pendingCiphertext);
            wipe(pendingIv);
            pendingCiphertext = null;
            pendingIv = null;
            senderCase = null;
            transferId = null;
            localPairApproved = false;
            peerPairApproved = false;
            secureReady = false;
            outstandingRequest = null;
            senderRole = false;
        }

        private void decryptAndPreview() {
            if (senderRole || !secureReady || !localPairApproved || pendingCiphertext == null
                    || pendingIv == null || encryptionKey == null) {
                activity.postStatus("No encrypted case is available to decrypt. Verify the short code first.");
                return;
            }
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encryptionKey, "AES"), new GCMParameterSpec(128, pendingIv));
                cipher.updateAAD(transcriptHash);
                byte[] plaintext = cipher.doFinal(pendingCiphertext);
                if (plaintext.length > MAX_PLAINTEXT_BYTES) throw new IllegalArgumentException("Plaintext size");
                JSONObject received = activity.sanitizeCase(new JSONObject(new String(plaintext, StandardCharsets.UTF_8)));
                Arrays.fill(plaintext, (byte) 0);
                if (received == null) throw new IllegalArgumentException("Case schema/consent");
                JSONObject payload = new JSONObject();
                payload.put("transferId", transferId);
                payload.put("caseData", received);
                wipe(pendingCiphertext);
                wipe(pendingIv);
                pendingCiphertext = null;
                pendingIv = null;
                if (transferTimeout != null) handler.removeCallbacks(transferTimeout);
                transferTimeout = null;
                clearCryptoState();
                activity.postIncoming(payload);
            } catch (Exception e) {
                rejectSession("Could not authenticate/decrypt the case. It was discarded and not imported.");
            }
        }

        private static void wipe(byte[] value) {
            if (value != null) Arrays.fill(value, (byte) 0);
        }

        private static byte[] randomBytes(int count) {
            byte[] bytes = new byte[count];
            SECURE_RANDOM.nextBytes(bytes);
            return bytes;
        }

        private static KeyPair newEphemeralKeyPair() throws Exception {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"), SECURE_RANDOM);
            return generator.generateKeyPair();
        }

        private static byte[] hkdf(byte[] inputKey, byte[] salt, byte[] info, int size) throws Exception {
            byte[] prk = hmac(salt, inputKey);
            ByteArrayOutputStream result = new ByteArrayOutputStream(size);
            byte[] previous = new byte[0];
            for (int i = 1; result.size() < size; i++) {
                previous = hmac(prk, concat(previous, info, new byte[]{(byte) i}));
                result.write(previous, 0, previous.length);
            }
            byte[] okm = Arrays.copyOf(result.toByteArray(), size);
            wipe(prk);
            wipe(previous);
            return okm;
        }

        private static byte[] hmac(byte[] key, byte[] data) throws Exception {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        }

        private static byte[] concat(byte[]... inputs) {
            int length = 0;
            for (byte[] input : inputs) length += input.length;
            byte[] result = new byte[length];
            int offset = 0;
            for (byte[] input : inputs) {
                System.arraycopy(input, 0, result, offset, input.length);
                offset += input.length;
            }
            return result;
        }

        private boolean beginWithPermissions(String operation) {
            if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
                activity.postStatus("Update Android System WebView to use secure Bluetooth transfer.");
                return false;
            }
            String[] missing = missingPermissions();
            if (missing.length > 0) {
                pendingOperation = operation;
                activity.requestPermissions(missing, REQUEST_PERMISSIONS);
                activity.postStatus("Bluetooth needs the requested nearby-device permission to scan or receive. Allow it to continue.");
                return false;
            }
            return true;
        }

        private String[] missingPermissions() {
            List<String> missing = new ArrayList<>();
            if (Build.VERSION.SDK_INT >= 31) {
                addIfMissing(missing, Manifest.permission.BLUETOOTH_SCAN);
                addIfMissing(missing, Manifest.permission.BLUETOOTH_CONNECT);
                addIfMissing(missing, Manifest.permission.BLUETOOTH_ADVERTISE);
            } else {
                addIfMissing(missing, Manifest.permission.ACCESS_FINE_LOCATION);
            }
            return missing.toArray(new String[0]);
        }

        private void addIfMissing(List<String> missing, String permission) {
            if (activity.checkSelfPermission(permission) != PackageManager.PERMISSION_GRANTED) {
                missing.add(permission);
            }
        }

        void onPermissionsResult(int requestCode, int[] grantResults) {
            if (requestCode != REQUEST_PERMISSIONS || pendingOperation == null) return;
            String operation = pendingOperation;
            pendingOperation = null;
            if (grantResults.length == 0) {
                pendingAddress = null;
                pendingCaseData = null;
                activity.postStatus("Bluetooth permission was not granted. Allow Nearby devices and retry.");
                return;
            }
            for (int grant : grantResults) {
                if (grant != PackageManager.PERMISSION_GRANTED) {
                    pendingAddress = null;
                    pendingCaseData = null;
                    activity.postStatus("Bluetooth permission was denied. Allow Nearby devices (and Location on older Android) in Settings to transfer.");
                    return;
                }
            }
            if ("scan".equals(operation)) startScan();
            else if ("receive".equals(operation)) startReceiving();
            else if ("send".equals(operation)) {
                String address = pendingAddress;
                JSONObject data = pendingCaseData;
                pendingAddress = null;
                pendingCaseData = null;
                if (address != null && data != null) send(address, data);
                else activity.postStatus("Permission granted. Select the intended recipient and confirm sending again.");
            }
        }

        private boolean usableAdapter() {
            if (adapter == null) {
                activity.postStatus("This phone has no Bluetooth adapter.");
                return false;
            }
            try {
                if (!adapter.isEnabled()) {
                    activity.postStatus("Bluetooth is turned off. Turn it on in Android Settings, then try again.");
                    return false;
                }
            } catch (SecurityException e) {
                activity.postStatus("Bluetooth permission is missing. Grant Nearby devices permission in Android Settings.");
                return false;
            }
            return true;
        }

        private void beginAdvertising() {
            advertiser = adapter.getBluetoothLeAdvertiser();
            if (advertiser == null) {
                activity.postStatus("BLE advertising is unavailable on this phone.");
                return;
            }
            AdvertiseSettings settings = new AdvertiseSettings.Builder()
                    .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                    .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_LOW)
                    .setConnectable(true)
                    .setTimeout(0)
                    .build();
            AdvertiseData data = new AdvertiseData.Builder()
                    .setIncludeDeviceName(false)
                    .addServiceUuid(new ParcelUuid(SERVICE_UUID))
                    .build();
            advertiseCallback = new AdvertiseCallback() {
                @Override
                public void onStartSuccess(AdvertiseSettings settingsInEffect) {
                    receiving = true;
                    activity.postStatus("Ready to receive nearby case transfers. Nothing is saved unless you preview and accept a case.");
                }

                @Override
                public void onStartFailure(int errorCode) {
                    receiving = false;
                    activity.postStatus("Could not advertise for receiving (" + errorCode + "). Close other BLE apps, check Bluetooth permissions, and retry.");
                }
            };
            try {
                advertiser.startAdvertising(settings, data, advertiseCallback);
            } catch (SecurityException | IllegalStateException e) {
                activity.postStatus("BLE advertising failed. Check Nearby devices permission, range, and device support.");
            }
        }

        void send(String address, JSONObject caseData) {
            if (!beginWithPermissions("send")) {
                if (pendingOperation != null) {
                    pendingAddress = address;
                    pendingCaseData = caseData;
                }
                return;
            }
            if (!usableAdapter()) return;
            BluetoothDevice device = discovered.get(address);
            if (device == null) {
                activity.postStatus("That recipient is no longer in the nearby-device list. Scan again and select them explicitly.");
                return;
            }
            try {
                clearCryptoState();
                senderCase = caseData;
                if (senderCase.toString().getBytes(StandardCharsets.UTF_8).length > MAX_PLAINTEXT_BYTES) {
                    senderCase = null;
                    activity.postStatus("This case is too large for Bluetooth transfer (maximum 48 KiB of case data). Attachments and voice notes are not included.");
                    return;
                }
                stopScan();
                closeCentral();
                centralGatt = device.connectGatt(activity, false, centralCallback, BluetoothDevice.TRANSPORT_LE);
                if (centralGatt == null) {
                    senderCase = null;
                    activity.postStatus("Could not connect to the selected recipient. Check range and retry.");
                } else {
                    activity.postStatus("Connecting to the selected recipient… Keep both phones nearby.");
                    transferTimeout = () -> {
                        closeCentral();
                        clearCryptoState();
                        outgoingPackets = null;
                        activity.postStatus("Bluetooth transfer timed out or lost range. No delivery is claimed; retry when both phones are ready.");
                    };
                    handler.postDelayed(transferTimeout, 90_000);
                }
            } catch (SecurityException | IllegalArgumentException e) {
                clearCryptoState();
                activity.postStatus("Bluetooth could not connect to the selected phone. Check permission, Bluetooth state, and range.");
            }
        }

        private final BluetoothGattCallback centralCallback = new BluetoothGattCallback() {
            @Override
            public void onConnectionStateChange(BluetoothGatt gatt, int status, int newState) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    failTransfer("Connection failed (" + status + "). Check range and retry.");
                    return;
                }
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    try {
                        if (!gatt.requestMtu(517)) gatt.discoverServices();
                    } catch (SecurityException e) {
                        failTransfer("Bluetooth permission was revoked during connection.");
                    }
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED && senderCase != null) {
                    failTransfer("The recipient disconnected before secure transfer completed. Check range and retry.");
                }
            }

            @Override
            public void onMtuChanged(BluetoothGatt gatt, int negotiatedMtu, int status) {
                if (status == BluetoothGatt.GATT_SUCCESS && negotiatedMtu >= 23) mtu = negotiatedMtu;
                try {
                    if (!gatt.discoverServices()) {
                        failTransfer("Could not start discovery of the recipient transfer service.");
                    }
                } catch (SecurityException e) {
                    failTransfer("Bluetooth permission was revoked while connecting.");
                }
            }

            @Override
            public void onServicesDiscovered(BluetoothGatt gatt, int status) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    failTransfer("Could not discover the recipient transfer service.");
                    return;
                }
                BluetoothGattService service = gatt.getService(SERVICE_UUID);
                centralWriteCharacteristic = service == null ? null : service.getCharacteristic(CHARACTERISTIC_UUID);
                centralReplyCharacteristic = service == null ? null : service.getCharacteristic(REPLY_UUID);
                BluetoothGattDescriptor descriptor = centralReplyCharacteristic == null
                        ? null : centralReplyCharacteristic.getDescriptor(CCCD_UUID);
                if (centralWriteCharacteristic == null || centralReplyCharacteristic == null || descriptor == null) {
                    failTransfer("The selected phone is not ready to receive this case.");
                    return;
                }
                try {
                    if (!gatt.setCharacteristicNotification(centralReplyCharacteristic, true)) {
                        failTransfer("Could not enable secure Bluetooth responses from the recipient.");
                        return;
                    }
                    boolean queued;
                    if (Build.VERSION.SDK_INT >= 33) {
                        queued = gatt.writeDescriptor(descriptor, BluetoothGattDescriptor.ENABLE_INDICATION_VALUE)
                                == BluetoothGatt.GATT_SUCCESS;
                    } else {
                        descriptor.setValue(BluetoothGattDescriptor.ENABLE_INDICATION_VALUE);
                        queued = gatt.writeDescriptor(descriptor);
                    }
                    if (!queued) failTransfer("Could not enable the secure response channel.");
                } catch (SecurityException e) {
                    failTransfer("Bluetooth permission was revoked during service setup.");
                }
            }

            @Override
            public void onDescriptorWrite(BluetoothGatt gatt, BluetoothGattDescriptor descriptor, int status) {
                if (status != BluetoothGatt.GATT_SUCCESS || !CCCD_UUID.equals(descriptor.getUuid())) {
                    failTransfer("Could not establish the secure BLE response channel.");
                    return;
                }
                beginSenderHandshake();
            }

            @Override
            public void onCharacteristicWrite(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic, int status) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    failTransfer("Bluetooth chunk write failed (" + status + "). Check range and retry.");
                    return;
                }
                outgoingIndex++;
                writeNextPacket(gatt);
            }

            @Override
            public void onCharacteristicChanged(
                    BluetoothGatt gatt, BluetoothGattCharacteristic characteristic, byte[] value) {
                if (REPLY_UUID.equals(characteristic.getUuid())) handleServerFrame(value);
            }

            @Override
            public void onCharacteristicChanged(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic) {
                if (Build.VERSION.SDK_INT < 33 && REPLY_UUID.equals(characteristic.getUuid())) {
                    handleServerFrame(characteristic.getValue());
                }
            }
        };

        private void handleServerFrame(byte[] frame) {
            try {
                JSONObject message = receiveServerFrame(frame);
                if (message != null) handleServerReply(message);
            } catch (Exception e) {
                failTransfer("A secure Bluetooth response was invalid. The transfer was cancelled.");
            }
        }

        private void writeNextPacket(BluetoothGatt gatt) {
            if (outgoingPackets == null || outgoingIndex >= outgoingPackets.size()) {
                outgoing = null;
                outgoingPackets = null;
                return;
            }
            try {
                byte[] packet = outgoingPackets.get(outgoingIndex);
                boolean started;
                if (Build.VERSION.SDK_INT >= 33) {
                    started = gatt.writeCharacteristic(
                            centralWriteCharacteristic, packet, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT)
                            == BluetoothGatt.GATT_SUCCESS;
                } else {
                    centralWriteCharacteristic.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
                    centralWriteCharacteristic.setValue(packet);
                    started = gatt.writeCharacteristic(centralWriteCharacteristic);
                }
                if (!started) failTransfer("Could not queue a Bluetooth data chunk. Check range and retry.");
            } catch (SecurityException e) {
                failTransfer("Bluetooth permission was revoked while sending.");
            }
        }

        private void failTransfer(String message) {
            if (transferTimeout != null) handler.removeCallbacks(transferTimeout);
            closeCentral();
            outgoing = null;
            outgoingPackets = null;
            clearCryptoState();
            activity.postStatus(message);
        }

        private void stopScan() {
            if (scanTimeout != null) handler.removeCallbacks(scanTimeout);
            scanTimeout = null;
            if (scanner != null && scanCallback != null) {
                try {
                    scanner.stopScan(scanCallback);
                } catch (SecurityException ignored) {
                }
            }
            scanCallback = null;
            scanner = null;
        }

        private void stopAdvertising() {
            if (advertiser != null && advertiseCallback != null) {
                try {
                    advertiser.stopAdvertising(advertiseCallback);
                } catch (SecurityException ignored) {
                }
            }
            advertiseCallback = null;
            advertiser = null;
            receiving = false;
        }

        private void stopReceiving() {
            stopAdvertising();
            if (server != null) {
                try {
                    server.close();
                } catch (SecurityException ignored) {
                }
                server = null;
            }
            serverWriteCharacteristic = null;
            serverReplyCharacteristic = null;
            centralWriteCharacteristic = null;
            centralReplyCharacteristic = null;
            serverPeer = null;
            serverNotifyQueue.clear();
            serverIndicationActive = false;
            resetReceiveBuffer();
            clearCryptoState();
        }

        void discardIncoming() {
            resetReceiveBuffer();
            clearCryptoState();
            if (serverPeer != null) {
                try {
                    if (server != null) server.cancelConnection(serverPeer);
                } catch (SecurityException ignored) {
                }
                serverPeer = null;
            }
        }

        private void resetReceiveBuffer() {
            if (transferTimeout != null) handler.removeCallbacks(transferTimeout);
            transferTimeout = null;
            if (receivedChunks != null) {
                for (byte[] chunk : receivedChunks) {
                    if (chunk != null) Arrays.fill(chunk, (byte) 0);
                }
            }
            receivedChunks = null;
            expectedBytes = 0;
            receivedCount = 0;
            receivedByteCount = 0;
            incomingChunkCount = 0;
        }

        private void closeCentral() {
            if (centralGatt != null) {
                try {
                    centralGatt.disconnect();
                    centralGatt.close();
                } catch (SecurityException ignored) {
                }
                centralGatt = null;
            }
        }

        void close() {
            stopScan();
            stopReceiving();
            failTransfer("Bluetooth transfer stopped.");
        }
    }
}
