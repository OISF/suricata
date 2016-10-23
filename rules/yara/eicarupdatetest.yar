rule eicar_testing_update : test
{
    meta:
        description = "Example yara rule #0 for eicar"
        threat_level = 3
        in_the_wild = true

    strings:
        $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

    condition:
        $a
}
