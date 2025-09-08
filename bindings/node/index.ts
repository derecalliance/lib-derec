import {
    ts_protect_secret,
    ts_generate_verification_request,
    ts_generate_verification_response,
    ts_verify_share_response,
    ts_generate_share_request,
    ts_generate_share_response,
    ts_recover_from_share_responses
} from "derec-library";

const secret_id = new Uint8Array([1, 2, 3, 4, 255]);
const secret_data = new Uint8Array([5, 6, 7, 8, 255]);
const channels = new BigUint64Array([1n, 2n, 3n]);
const threshold = 2;
const version = 1;

let shares = ts_protect_secret(secret_id, secret_data, channels, threshold, version);
let some_share = shares.value.get(1);
let some_channel = 1n;
console.log("ts_protect_secret: ", shares);
let request = ts_generate_verification_request(secret_id, version);
console.log("ts_generate_verification_request: ", request);
let response = ts_generate_verification_response(secret_id, some_channel, some_share, request);
console.log("ts_generate_verification_response: ", response);
let verification_expected_true = ts_verify_share_response(secret_id, some_channel, some_share, response);
console.log("ts_verify_share_response (expected true): ", verification_expected_true);
let verification = ts_verify_share_response(secret_id, 1n, shares.value.get(2), response);
console.log("ts_verify_share_response (expected false): ", verification);

let share_request = ts_generate_share_request(1n, secret_id, version);
console.log("ts_generate_share_request: ", share_request);
let share_response_1 = ts_generate_share_response(secret_id, 1n, shares.value.get(1), share_request);
console.log("ts_generate_share_response: ", share_response_1);
let share_response_2 = ts_generate_share_response(secret_id, 2n, shares.value.get(2), share_request);
console.log("ts_generate_share_response: ", share_response_2);
let share_response_3 = ts_generate_share_response(secret_id, 3n, shares.value.get(3), share_request);
console.log("ts_generate_share_response: ", share_response_3);

const responses = new Map<number, number[]>();
responses.set(1, Array.from(share_response_1));
responses.set(2, Array.from(share_response_2));
responses.set(3, Array.from(share_response_3));
try {
    let recovered = ts_recover_from_share_responses({"value": responses}, secret_id, version);
    console.log("ts_recover_from_share_responses: ", recovered);
} catch (e) {
    console.error("Error recovering from share responses: ", e);
}