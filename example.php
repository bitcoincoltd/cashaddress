<?php
$validAddresses = [
    "bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r",
    "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
    "bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy",
    "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq",
    "bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e",
    "bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37",

    "qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r",
    "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
    "qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy",
    "ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq",
    "pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e",
    "pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37",

    "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu",
    "1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR",
    "16w1D5WRVKJuZUsSRzdLp9w3YGcgoxDXb",
    "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC",
    "3LDsS579y7sruadqu11beEJoTjdFiFCdX4",
    "31nwvkZwyPdgzjBJZXfDmSWsC4ZLKpYyUw"
];

foreach ($validAddresses as $addr) {
    echo valid($addr) ? "OK" : "FAIL";
    echo ": " . $addr . "\n";
}

include_once(__DIR__.'/bch.cashaddress.php');

function valid($addr) {
    if (strpos($addr, ":") === false) {
        $addr = "bitcoincash:" . $addr;
    }

    try {
        CashAddress::decode($addr);
    } catch (Base32Exception $e) {
        return false;
    } catch (CashAddressException $e) {
        return false;
    }

    return true;
}
