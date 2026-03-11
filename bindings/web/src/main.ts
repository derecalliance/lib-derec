import init, {
    protect_secret,
    generate_verification_request,
    generate_verification_response,
    verify_share_response,
    generate_share_request,
    generate_share_response,
    recover_from_share_responses,
    create_contact_message,
    produce_pairing_request_message,
    produce_pairing_response_message,
    process_pairing_response_message
} from "@derecalliance/derec-web";

async function main() {
    await init();

    const secret_id = new Uint8Array([1, 2, 3, 4, 255]);
    const secret_data = new Uint8Array([5, 6, 7, 8, 255]);
    const channels = new BigUint64Array([1n, 2n, 3n]);
    const threshold = 2;
    const version = 1;

    const shares = protect_secret(secret_id, secret_data, channels, threshold, version);
    const some_share = shares.value.get(1);
    const some_channel = 1n;

    console.log("protect_secret: ", shares);

    const request = generate_verification_request(secret_id, version);
    console.log("generate_verification_request: ", request);

    const response = generate_verification_response(secret_id, some_channel, some_share, request);
    console.log("generate_verification_response: ", response);

    const verification_expected_true = verify_share_response(
        secret_id,
        some_channel,
        some_share,
        response
    );
    console.log("verify_share_response (expected true): ", verification_expected_true);

    const verification = verify_share_response(
        secret_id,
        1n,
        shares.value.get(2),
        response
    );
    console.log("verify_share_response (expected false): ", verification);

    const share_request = generate_share_request(1n, secret_id, version);
    console.log("generate_share_request: ", share_request);

    const share_response_1 = generate_share_response(
        secret_id,
        1n,
        shares.value.get(1),
        share_request
    );
    console.log("generate_share_response: ", share_response_1);

    const share_response_2 = generate_share_response(
        secret_id,
        2n,
        shares.value.get(2),
        share_request
    );
    console.log("generate_share_response: ", share_response_2);

    const share_response_3 = generate_share_response(
        secret_id,
        3n,
        shares.value.get(3),
        share_request
    );
    console.log("generate_share_response: ", share_response_3);

    const responses = new Map<number, number[]>();
    responses.set(1, Array.from(share_response_1));
    responses.set(2, Array.from(share_response_2));
    responses.set(3, Array.from(share_response_3));

    try {
        const recovered = recover_from_share_responses({ value: responses }, secret_id, version);
        console.log("recover_from_share_responses: ", recovered);
    } catch (e) {
        console.error("Error recovering from share responses: ", e);
    }

    console.log("--------------------   Pairing Functions   --------------------");

    const channel_id = 1n;
    const role_helper = 2;
    const role_sharer = 0;

    // run by Alice, who then produces the QR code
    const create_contact_message_result = create_contact_message(
        channel_id,
        "https://example.com/alice"
    );
    console.log("create_contact_message: ", create_contact_message_result);

    // run by Bob, who scans Alice's QR code
    const produce_pairing_request_message_result = produce_pairing_request_message(
        channel_id,
        role_helper,
        create_contact_message_result.contact_message
    );
    console.log(
        "produce_pairing_request_message: ",
        produce_pairing_request_message_result
    );

    // run by Alice, who receives Bob's pairing request message
    const produce_pairing_response_message_result = produce_pairing_response_message(
        role_sharer,
        produce_pairing_request_message_result.pair_request_message,
        create_contact_message_result.secret_key_material
    );
    console.log(
        "produce_pairing_response_message: ",
        produce_pairing_response_message_result
    );

    // run by Bob, who receives Alice's pairing response message
    const process_pairing_response_message_result = process_pairing_response_message(
        create_contact_message_result.contact_message,
        produce_pairing_response_message_result.pair_response_message,
        produce_pairing_request_message_result.secret_key_material
    );
    console.log(
        "process_pairing_response_message: ",
        process_pairing_response_message_result
    );

    const app = document.getElementById("app");
    if (app) {
        app.textContent = "DeRec web smoke test completed. Check the browser console.";
    }
}

main().catch((error) => {
    console.error("Web smoke test failed:", error);

    const app = document.getElementById("app");
    if (app) {
        app.textContent = `DeRec web smoke test failed: ${String(error)}`;
    }
});
