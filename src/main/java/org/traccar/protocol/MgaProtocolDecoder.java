package org.traccar.protocol;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.traccar.BaseProtocolDecoder;
import org.traccar.handler.network.MainEventHandler;
import org.traccar.session.DeviceSession;
import org.traccar.Protocol;
import org.traccar.model.CellTower;
import org.traccar.model.Network;
import org.traccar.model.Position;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.SocketAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

public class MgaProtocolDecoder extends BaseProtocolDecoder {

    public MgaProtocolDecoder(Protocol protocol) {
        super(protocol);
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(MgaProtocolDecoder.class);

    @Override
    protected Object decode(
            Channel channel, SocketAddress remoteAddress, Object msg) throws Exception {

        System.out.println("====== MGA DECODE CALLED ======");

        ByteBuf buf = (ByteBuf) msg;
        return decodeBinary(buf, channel, remoteAddress);
    }

    private List<Position> decodeBinary(ByteBuf buf, Channel channel, SocketAddress remoteAddress)
            throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException {

        List<Position> positions = new LinkedList<>();

        if (buf.readableBytes() < 1) {
            return null;
        }
        // *******************************Frame*******************************

        LOGGER.info("~~ Received {}Bytes --- Starting Decode ~~", buf.readableBytes());

        /* Search for the Start of Frame (1 Byte) */
        byte sof = buf.readByte();
        if (sof != (byte) 0xAA) {
            for (int i = 1; i <= buf.readableBytes(); i++) {
                sof = buf.readByte();
                if (buf.readableBytes() < 1 || sof == (byte) 0xAA) {
                    System.out.println("Start frame not found");
                    return null;
                }
            }
        }

        /* Extract Expected Length (2 Bytes) */
        int length = Short.reverseBytes(buf.readShort()) & 0xFFFF;

        LOGGER.info("SOF: {} | EXPECTED LEN: {}B | RECEIVED LEN: {}B", sof, length + 1, buf.readableBytes());
        if (buf.readableBytes() < length + 1) {
            System.out.println("Expected len LESS THAN received len");
            LOGGER.info("ERROR: Expected len {}B LESS THAN received len {}B", length + 1, buf.readableBytes());
            return null;
        }

        /* Extract Serial Number (4 Bytes) */
        int serialNumber = Integer.reverseBytes(buf.readInt());

        LOGGER.info("Serial Number: {}", serialNumber);
        System.out.print("Serial Number :");
        System.out.println(serialNumber);

        String id = String.valueOf(serialNumber);
        DeviceSession deviceSession = getDeviceSession(channel, remoteAddress, id);
        if (deviceSession == null) {
            return null;
        }

        /* Extract Encrypted Payload (Length - 6 Bytes) */
        int encryptedPayloadSize = length - 6;
        byte[] encryptedPayload = new byte[encryptedPayloadSize];
        buf.readBytes(encryptedPayload);
        // LOGGER.info("Encrypted Payload: {}", encryptedPayload);

        /* Extract Expected CRC Checksum, MODBUS CRC (2 Bytes) */
        int receivedCRC = buf.readUnsignedShort();
        LOGGER.info("Received CRC: {}", receivedCRC);
        int expectedCRC = receivedCRC;
        if (receivedCRC != expectedCRC) {
            LOGGER.info("Received CRC: {} != Expected CRC", receivedCRC, expectedCRC);
            return null;
        }
        /* CRC check can be implemented here */

        /* Extract End of Frame (EOF) */
        byte eof = buf.readByte();
        if (eof != (byte) 0x55) {
            LOGGER.info("EOF: {} != 0x55", eof);
            return null;
        }
        // *******************************Payload*******************************
        // --- Prepare cipher ---
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        for (int i = 0; i < 16; i++) {
            key[i] = (byte) i;
            iv[i] = (byte) (i + 0x10);
        }
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        // cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        /* Start of Payload (1 Byte) */
        byte[] decrypted = encryptedPayload;
        byte sop = encryptedPayload[0];
        if (sop != (byte) 0xAB) {
            // LOGGER.info("encrypted Payload: {}", encryptedPayload);
            decrypted = cipher.doFinal(encryptedPayload);
            // LOGGER.info("decrypted: {}", decrypted);
            LOGGER.info("Decrypting payload .... ");
        }

        /* Decrypted Data Payload */
        int decryptedSize = length - 6;
        ByteBuf decryptedBuf = Unpooled.wrappedBuffer(decrypted);
        sop = decryptedBuf.readByte();
        if (sop != (byte) 0xAB) {
            LOGGER.info("Failed to decrypt: SOP={} != 0xAB", sop);
            return null;
        }

        /* Packet Count (1 Byte) */
        int packetCount = decryptedBuf.readByte();
        LOGGER.info("Payload decrypted successfully! Received {} Packets", packetCount);

        /* Combined Packets (Decrypted Size - 3 Byte) */
        int packetsCombinedSize = decryptedSize - 3;
        byte[] packetsCombined = new byte[packetsCombinedSize];
        decryptedBuf.readBytes(packetsCombined);
        // LOGGER.info("Packets Combined Size: {}", packetsCombinedSize);
        // LOGGER.info("Packets Combined: {}", packetsCombined);

        // End of Packet (1 Byte)
        byte eop = decryptedBuf.readByte();
        if (eop != (byte) 0x57) {
            LOGGER.info("ERROR: EOP: {} != 0x57", eop);
            return null;
        }

        // *******************************Packets*******************************
        /* Read the combined packets into dataBuf for further processing */
        ByteBuf dataBuf = Unpooled.wrappedBuffer(packetsCombined);

        /* Read packets received from dataBuf one by one, packetCount times. */
        for (int i = 0; i < packetCount; i++) {
            // LOGGER.info("packet number: {}", i);

            /*
             * Set the device ID of the position packet,
             * based on the previously processed Serial Number
             */
            Position position = new Position(getProtocolName());
            position.setDeviceId(deviceSession.getDeviceId());

            /* If the data is shorter than expected, return. */
            if (dataBuf.readableBytes() < 4) {
                LOGGER.info("ERROR: Data Shorter than 4 Bytes");
                System.out.println("ERROR: Data Shorter than 4 Bytes");
                break;
            }

            /* Extract the Start of Data (1 Byte) */
            byte sod = dataBuf.readByte();
            if (sod != (byte) 0xAF) {
                for (int j = 1; j <= buf.readableBytes(); j++) {
                    sod = dataBuf.readByte();
                    if (dataBuf.readableBytes() < 4 || sod == (byte) 0xAF) {
                        break;
                    }
                }
                if (dataBuf.readableBytes() < 4) {
                    break;
                }
            }
            /* Reaching this point, means the SOD has been found. */

            /* Extract the Type (1 Byte) */
            int dataType = dataBuf.readUnsignedByte();
            // LOGGER.info("Data Type: {}", dataType);
            if (dataType != 33) {

                System.out.print("ERROR: Data Type not 33 , its : ");
                System.out.println(dataType);

                continue;
            }

            // LOGGER.info("Passed: {}", dataType);

            /* Extract the Length (1 Byte) */
            int dataLength = dataBuf.readUnsignedByte();

            /* Extract the Data (Length Bytes) */
            if (dataBuf.readableBytes() < dataLength) {
                LOGGER.info("ERROR: Expected Data Length={} > Remaining Data Length={}", dataType,
                        dataBuf.readableBytes());
                break;
            }

            /*
             * Load dataLength bytes of dataBuf for processing,
             * this is the data containing information based on the
             * packet type.
             */
            byte[] data = new byte[dataLength];
            dataBuf.readBytes(data);
            // LOGGER.info("data: {}",
            // ByteBufUtil.hexDump(Unpooled.wrappedBuffer(data)).replaceAll("(.{2})", "$1
            // "));

            /* End of Data (1 Byte) */
            byte eod = dataBuf.readByte();
            if (eod != (byte) 0x5F) {
                LOGGER.info("ERROR: EOD={} != 0x5F", eod);
                break;
            }

            LOGGER.info("Processing Packet: {}/{}, Type={}, Length={}", i + 1, packetCount, dataType, dataLength);

            ByteBuf wrappedData = Unpooled.wrappedBuffer(data);

            /* Extract the Alarm Code (2 Byte) */
            int alarmCode = Short.reverseBytes(wrappedData.readShort());
            findAlarm(alarmCode, position);

            /* Flags P1 */
            int flags1 = wrappedData.readByte();

            /* Extract flag one - bit four: Simcard slot in use */
            boolean isSimTwo;
            isSimTwo = (flags1 & 0b00001000) != 0;
            int simSlot = 1;
            if (isSimTwo) {
                simSlot = 2;
            }
            position.set(Position.KEY_SIM_SLOT, simSlot);
            // System.out.print("KEY_SIM_SLOT: ");
            // System.out.println(simSlot);

            /* Extract flag one - bit five: Charge status */
            boolean isCharging;
            isCharging = (flags1 & 0b00010000) != 0;
            position.set(Position.KEY_CHARGE, isCharging);
            // System.out.print("KEY_CHARGE: ");
            // System.out.println(isCharging);

            /* Extract flag one - bit six: GNSS fix status (0 = not fixed, 1 = fixed) */
            boolean isFixed;
            isFixed = (flags1 & 0b00100000) != 0;
            position.setValid(isFixed);
            // System.out.print("fixed: ");
            // System.out.println(isFixed);

            /* Extract flag one - bit seven: GNSS stop status (0 = moving, 1 = stopped) */
            boolean isStop;
            isStop = (flags1 & 0b01000000) != 0;
            position.set(Position.KEY_MOTION, !isStop);
            // System.out.print("KEY_MOTION: ");
            // System.out.println(!isStop);

            /* Extract flag one - bit eight: LAC/CID Validity (0 = Not Valid, 1 = Valid) */
            // boolean lacCidValidity;
            // lacCidValidity = (flags1 & 0b10000000) != 0;

            int flags2 = wrappedData.readByte();

            /* Extract flag two - bit one: Unlock Status (0 = Not Allowed, 1 = Allowed) */
            boolean isUnlockAllowed;
            isUnlockAllowed = (flags2 & 0b00000001) != 0;
            position.set(Position.KEY_LOCK, isUnlockAllowed);
            // System.out.print("KEY_LOCK: ");
            // System.out.println(isUnlockAllowed);

            /* Extract flag two - bit two: Rope Status (0 = Open, 1 = Closed) */
            boolean isRopeClosed;
            isRopeClosed = (flags2 & 0b00000010) != 0;
            position.set(Position.KEY_WIRE_TAMPER, isRopeClosed);
            // System.out.print("KEY_WIRE_TAMPER: ");
            // System.out.println(isRopeClosed);

            /* Extract flag two - bit three: Mechanical Status (0 = Open, 1 = Closed) */
            boolean isMechanicClosed;
            isMechanicClosed = (flags2 & 0b00000100) != 0;
            position.set(Position.KEY_MECHANIC_CLOSE, isMechanicClosed);

            /* Extract flag two - bit four: Coil Status (0 = Deactive, 1 = Active) */
            boolean isCoilOpen;
            isCoilOpen = (flags2 & 0b00001000) != 0;
            position.set(Position.KEY_COIL_OPEN, isCoilOpen);

            /* Extract flag two - bit five: Extended packet status (1 = extended packet) */
            // boolean isExtended;
            // isExtended = (flags2 & 0b00010000) != 0;

            /* Extract the Geofences bitwise flags (2 Byte) */
            long geofences = Short.reverseBytes(wrappedData.readShort());
            position.set(Position.KEY_GEOFENCE_MASK, geofences);

            // reserve
            Short.reverseBytes(wrappedData.readShort());

            /* Extract the Battery Voltage (2 Byte) */
            double batteryVoltage = (double) Short.reverseBytes(wrappedData.readShort());
            position.set(Position.KEY_BATTERY_LEVEL, batteryVoltage);
            // System.out.print("KEY_BATTERY_LEVEL: ");
            // System.out.println(batteryVoltage);
            /* Extract the Temperature (1 Byte) */
            int temperature = wrappedData.readByte();
            position.set(Position.KEY_DEVICE_TEMP, temperature);
            // System.out.print("KEY_DEVICE_TEMP: ");
            // System.out.println(temperature);

            /* Extract the Humidity (1 Byte) */
            int humidity = wrappedData.readByte();
            position.set(Position.KEY_HUMIDITY, humidity);
            // System.out.print("KEY_HUMIDITY: ");
            // System.out.println(humidity);

            /* Extract the Unix Time (4 Bytes) */
            long unixTime = Integer.reverseBytes(wrappedData.readInt());
            Date date = new Date(unixTime * 1000L);
            position.setDeviceTime(date);
            // System.out.print("time: ");
            // System.out.println(date);

            /* Extract the Unix Time (4 Bytes) */
            long GPSDelay = Integer.reverseBytes(wrappedData.readInt());
            date = new Date((unixTime - GPSDelay) * 1000L);
            position.setFixTime(date);
            // System.out.print("gps delay: ");
            // System.out.println(date);

            /* Extract the Latitude (4 Bytes) */
            long lat = Integer.reverseBytes(wrappedData.readInt());
            double latitude = 0;
            latitude = (double) lat / 1000000;
            // System.out.print("lat: ");
            // System.out.println(latitude);
            if (latitude <= 90 && latitude >= -90) {
                position.setLatitude(latitude);
            }

            /* Extract the Longitude (4 Bytes) */
            long lon = Integer.reverseBytes(wrappedData.readInt());
            double longitude = 0;
            longitude = (double) lon / 1000000;
            // System.out.print("lon: ");
            // System.out.println(longitude);
            if (longitude <= 180 && longitude >= -180) {
                position.setLongitude(longitude);
            }

            /* Extract the bearing (2 Bytes) */
            long bearing = Short.reverseBytes(wrappedData.readShort());
            if (bearing < 360 && bearing >= 0) {
                position.setCourse(bearing);
            }

            // System.out.print("bearing: ");
            // System.out.println(bearing);

            /* Extract the PDOP (2 Bytes) */
            long PDOP = Short.reverseBytes(wrappedData.readShort());
            position.set(Position.KEY_PDOP, PDOP / 100);
            // System.out.print("PDOP: ");
            // System.out.println(PDOP / 100);

            /* Extract the Satellite (1 Byte) */
            int Satellite = wrappedData.readByte();
            position.set(Position.KEY_SATELLITES, Satellite);
            // System.out.print("KEY_SATELLITES: ");
            // System.out.println(Satellite);

            /* Extract the Speed (1 Byte) */
            int Speed = wrappedData.readByte();
            position.setSpeed(Speed);
            // System.out.print("Speed: ");
            // System.out.println(Speed);

            /* Extract the Unix Time (4 Bytes) */
            long BTSDelay = Integer.reverseBytes(wrappedData.readInt());
            position.set(Position.KEY_BTS_DELAY, BTSDelay);
            // System.out.print("BTS delay: ");
            // System.out.println(date);

            /* Extract the MNC (2 Byte) */
            int MNC = Short.reverseBytes(wrappedData.readShort());
            position.set(Position.KEY_MNC, MNC);
            // System.out.print("KEY_MNC: ");
            // System.out.println(MNC);

            /* Extract the MCC (2 Byte) */
            int MCC = Short.reverseBytes(wrappedData.readShort());
            position.set(Position.KEY_MCC, MCC);
            // System.out.print("KEY_MCC: ");
            // System.out.println(MCC);

            int Signal = wrappedData.readByte();
            position.set(Position.KEY_SIGNAL1, Signal);

            int Radio = wrappedData.readByte();
            position.set(Position.KEY_RADIO1, Radio);

            int LAC = Short.reverseBytes(wrappedData.readShort()) & 0xFFFF;
            position.set(Position.KEY_LAC1, LAC);
            // System.out.print("KEY_LAC1: ");
            // System.out.println(LAC);

            int CID = Integer.reverseBytes(wrappedData.readInt());
            position.set(Position.KEY_CID1, CID);
            if (CID != 0 && LAC != 0) {
                CellTower cellTower = CellTower.fromCidLac(getConfig(), CID, LAC);
                cellTower.setSignalStrength(Signal);
                cellTower.setMobileCountryCode(MCC);
                cellTower.setMobileNetworkCode(MNC);
                position.setNetwork(new Network(cellTower));
            } else {
                position.set(Position.KEY_RSSI, Signal);
            }
            /* Extract the BTS */
            boolean sixBts = (flags1 & 0b00000100) != 0;
            if (sixBts) {
                Signal = wrappedData.readByte();
                position.set(Position.KEY_SIGNAL2, Signal);

                Radio = wrappedData.readByte();
                position.set(Position.KEY_RADIO2, Radio);

                LAC = Short.reverseBytes(wrappedData.readShort()) & 0xFFFF;
                position.set(Position.KEY_LAC2, LAC);

                CID = Integer.reverseBytes(wrappedData.readInt());
                position.set(Position.KEY_CID2, CID);

                Signal = wrappedData.readByte();
                position.set(Position.KEY_SIGNAL3, Signal);

                Radio = wrappedData.readByte();
                position.set(Position.KEY_RADIO3, Radio);

                LAC = Short.reverseBytes(wrappedData.readShort()) & 0xFFFF;
                position.set(Position.KEY_LAC3, LAC);

                CID = Integer.reverseBytes(wrappedData.readInt());
                position.set(Position.KEY_CID3, CID);

                Signal = wrappedData.readByte();
                position.set(Position.KEY_SIGNAL4, Signal);

                Radio = wrappedData.readByte();
                position.set(Position.KEY_RADIO4, Radio);

                LAC = Short.reverseBytes(wrappedData.readShort()) & 0xFFFF;
                position.set(Position.KEY_LAC4, LAC);

                CID = Integer.reverseBytes(wrappedData.readInt());
                position.set(Position.KEY_CID4, CID);

                Signal = wrappedData.readByte();
                position.set(Position.KEY_SIGNAL5, Signal);

                Radio = wrappedData.readByte();
                position.set(Position.KEY_RADIO5, Radio);

                LAC = Short.reverseBytes(wrappedData.readShort()) & 0xFFFF;
                position.set(Position.KEY_LAC5, LAC);

                CID = Integer.reverseBytes(wrappedData.readInt());
                position.set(Position.KEY_CID5, CID);

                Signal = wrappedData.readByte();
                position.set(Position.KEY_SIGNAL6, Signal);

                Radio = wrappedData.readByte();
                position.set(Position.KEY_RADIO6, Radio);

                LAC = Short.reverseBytes(wrappedData.readShort()) & 0xFFFF;
                position.set(Position.KEY_LAC6, LAC);

                CID = Integer.reverseBytes(wrappedData.readInt());
                position.set(Position.KEY_CID6, CID);
            }

            /* Save the gathered position data */
            positions.add(position);

            System.out.print("Saving position for device: ");
            System.out.print(position.getDeviceId());
            System.out.print(" Alarm: ");
            System.out.print(position.getString(Position.KEY_ALARM));
            System.out.print(" Lat: ");
            System.out.print(position.getLatitude());
            System.out.print(" Lon: ");
            System.out.println(position.getLongitude());
        }

        System.out.println(positions);
        return positions;
    }

    private void findAlarm(int alarmCode, Position position) {
        System.out.print("Alarm Code : ");
        System.out.println(alarmCode);
        switch (alarmCode) {
            case 201:
                position.addAlarm(Position.ALARM_COURSE_CHANGE);
                break;
            case 202:
                position.addAlarm(Position.ALARM_OVER_SPEED_BEGIN);
                break;
            case 203:
                position.addAlarm(Position.ALARM_OVER_SPEED_END);
                break;
            case 204:
                position.addAlarm(Position.ALARM_LOCATION_TIMEOUT);
                break;
            case 205:
                position.addAlarm(Position.ALARM_SIGNAL_LOST);
                break;
            case 206:
                position.addAlarm(Position.ALARM_SIGNAL_BACK);
                break;
            case 207:
                position.addAlarm(Position.ALARM_STOP);
                break;
            case 208:
                position.addAlarm(Position.ALARM_MOVEMENT);
                break;
            case 209:
                position.addAlarm(Position.ALARM_CURRENT_STATUS);
                break;
            case 210:
                position.addAlarm(Position.ALARM_CHARGER_CONNECT);
                break;
            case 211:
                position.addAlarm(Position.ALARM_CHARGER_DISCONNECT);
                break;
            case 212:
                position.addAlarm(Position.ALARM_BUTTON_PRESSED);
                break;
            case 213:
                position.addAlarm(Position.ALARM_CONFIGURATION_CHANGE);
                break;
            case 214:
                position.addAlarm(Position.ALARM_LOCKER_UNSEALED);
                break;
            case 215:
                position.addAlarm(Position.ALARM_LOCKER_SEALED);
                break;
            case 216:
                position.addAlarm(Position.ALARM_TAMPER_OPENING);
                break;
            case 217:
                position.addAlarm(Position.ALARM_TAMPER_CLOSING);
                break;
            case 218:
                position.addAlarm(Position.ALARM_TEMPERATURE);
                break;
            case 219:
                position.addAlarm(Position.ALARM_TEMPERATURE);
                break;
            case 220:
                position.addAlarm(Position.ALARM_IMPACT);
                break;
            case 221:
                position.addAlarm(Position.ALARM_HUMIDITY);
                break;
            case 222:
                position.addAlarm(Position.ALARM_LOW_BATTERY);
                break;
            case 223:
                position.addAlarm(Position.ALARM_WRONG_PASSWORD);
                break;
            case 224:
                position.addAlarm(Position.ALARM_LONG_TIME_UNLOCKED);
                break;
            case 225:
                position.addAlarm(Position.ALARM_ILLEGAL_RFID);
                break;
            case 226:
                position.addAlarm(Position.ALARM_GEOFENCE_ENTER);
                break;
            case 227:
                position.addAlarm(Position.ALARM_GEOFENCE_EXIT);
                break;
            case 228:
                position.addAlarm(Position.ALARM_BACK_COVER_OPEN);
                break;
            case 229:
                position.addAlarm(Position.ALARM_TAMPER_OPENING);
                break;
            case 230:
                position.addAlarm(Position.ALARM_TAMPER_CLOSING);
                break;
            default:
                position.addAlarm(Position.ALARM_UNKNOWN);
                break;
        }
    }

}
