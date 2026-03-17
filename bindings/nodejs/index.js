import * as derec from "@derecalliance/derec-nodejs";
import { runDeRecMessageTest } from "./derec_message.js";
const secret_id = new Uint8Array([1, 2, 3, 4, 255]);
const secret_data = new Uint8Array([5, 6, 7, 8, 255]);
const channels = new BigUint64Array([1n, 2n, 3n]);
const threshold = 2;
const version = 1;
let shares = derec.protect_secret(secret_id, secret_data, channels, threshold, version);
let some_share = shares.value.get(1);
let some_channel = 1n;
console.log("protect_secret: ", shares);
let request = derec.generate_verification_request(secret_id, version);
console.log("generate_verification_request: ", request);
let response = derec.generate_verification_response(secret_id, some_channel, some_share, request);
console.log("generate_verification_response: ", response);
let verification_expected_true = derec.verify_share_response(secret_id, some_channel, some_share, response);
console.log("verify_share_response (expected true): ", verification_expected_true);
let verification = derec.verify_share_response(secret_id, 1n, shares.value.get(2), response);
console.log("verify_share_response (expected false): ", verification);
let share_request = derec.generate_share_request(1n, secret_id, version);
console.log("generate_share_request: ", share_request);
let share_response_1 = derec.generate_share_response(secret_id, 1n, shares.value.get(1), share_request);
console.log("generate_share_response: ", share_response_1);
let share_response_2 = derec.generate_share_response(secret_id, 2n, shares.value.get(2), share_request);
console.log("generate_share_response: ", share_response_2);
let share_response_3 = derec.generate_share_response(secret_id, 3n, shares.value.get(3), share_request);
console.log("generate_share_response: ", share_response_3);
const responses = new Map();
responses.set(1, Array.from(share_response_1));
responses.set(2, Array.from(share_response_2));
responses.set(3, Array.from(share_response_3));
try {
    let recovered = derec.recover_from_share_responses({ "value": responses }, secret_id, version);
    console.log("recover_from_share_responses: ", recovered);
}
catch (e) {
    console.error("Error recovering from share responses: ", e);
}
console.log("--------------------   Pairing Functions   --------------------");
let channel_id = 1n;
let role_helper = 2;
let role_sharer = 0;
// run by Alice, who then produces the QR code
let create_contact_message_result = derec.create_contact_message(channel_id, "https://example.com/alice");
console.log("create_contact_message: ", create_contact_message_result);
// run by Bob, who scans Alice's QR code
let produce_pairing_request_message_result = derec.produce_pairing_request_message(channel_id, role_helper, create_contact_message_result.contact_message);
console.log("produce_pairing_request_message: ", produce_pairing_request_message_result);
// run by Alice, who receives Bob's pairing request message
let produce_pairing_response_message_result = derec.produce_pairing_response_message(role_sharer, produce_pairing_request_message_result.pair_request_message, create_contact_message_result.secret_key_material);
console.log("produce_pairing_response_message: ", produce_pairing_response_message_result);
// run by Bob, who receives Alice's pairing response message
let process_pairing_response_message_result = derec.process_pairing_response_message(create_contact_message_result.contact_message, produce_pairing_response_message_result.pair_response_message, produce_pairing_request_message_result.secret_key_material);
console.log("process_pairing_response_message: ", process_pairing_response_message_result);
const validOwnerMessage = produce_pairing_request_message_result.pair_request_message;
console.log("pairRequestMessage:", validOwnerMessage);
console.log("is Uint8Array:", validOwnerMessage instanceof Uint8Array);
console.log("length:", validOwnerMessage?.length);
runDeRecMessageTest(derec, validOwnerMessage);
//# sourceMappingURL=index.js.map