# Suricata Developer Guide

This directory contains the Suricata Developer's Guide. It is built as part of the Suricata Userguide.

The Sequence Diagrams seen in the Transactions documentation are generated with Mscgen. Mscgen is a small program to parse Message Sequence Charts that can be represented as text and can then converted to image.

If you need to update the diagrams, please edit the ``.msc`` files present in the diagrams directory (extending/app-layer/diagrams). Once those have been changed, in the ``scripts`` directory (in the main Suricata dir) there's a scrip that will generate images for all files: ``generate-images.sh`` (you'll have to install Mscgen for that to work).

More info about Mscgen can be found at: https://www.mcternan.me.uk/mscgen/
