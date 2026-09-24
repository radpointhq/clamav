# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests for Excel 4.0 (XLM) macro extraction.
"""

import struct
import sys

sys.path.append('../unit_tests')
import testcase


SECTOR_SIZE = 512
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD


def _directory_entry(name, entry_type, child=FREESECT, start=ENDOFCHAIN, size=0):
    encoded_name = (name.encode('utf-16-le') + b'\x00\x00')[:64].ljust(64, b'\x00')
    name_length = min(len(name) * 2 + 2, 64)

    entry = encoded_name
    entry += struct.pack('<HBB', name_length, entry_type, 1)
    entry += struct.pack('<III', FREESECT, FREESECT, child)
    entry += b'\x00' * 16
    entry += struct.pack('<I', 0)
    entry += b'\x00' * 16
    entry += struct.pack('<IQ', start, size)

    assert len(entry) == 128
    return entry


def _write_xlm_formula_workbook(
    path,
    record_length,
    macro_sheet=True,
    token_tail=None,
    declared_token_length=None,
):
    """Write a minimal OLE2 workbook with a BIFF8 FORMULA record."""
    assert 0 <= record_length <= 8228

    boundsheet_data = struct.pack('<IBB', 0, 0, 1 if macro_sheet else 0)
    boundsheet = struct.pack('<HH', 0x0085, len(boundsheet_data)) + boundsheet_data

    token_length = max(record_length - 22, 0)
    if record_length >= 22:
        if declared_token_length is None:
            declared_token_length = token_length
        formula_header = b'\x00' * 20 + struct.pack('<H', declared_token_length)
    else:
        formula_header = b'\x00' * record_length
    if token_tail is None:
        formula_tokens = b'\x03' * token_length
    else:
        assert len(token_tail) <= token_length
        formula_tokens = b'\x03' * (token_length - len(token_tail)) + token_tail
    formula = struct.pack('<HH', 0x0006, record_length) + formula_header + formula_tokens

    workbook_stream = boundsheet + formula
    if len(workbook_stream) < 4096:
        padding_length = 4096 - len(workbook_stream) - 4
        workbook_stream += struct.pack('<HH', 0x003C, padding_length) + b'\x00' * padding_length

    stream_sector_count = (len(workbook_stream) + SECTOR_SIZE - 1) // SECTOR_SIZE
    stream_start = 2
    total_sector_count = stream_start + stream_sector_count
    assert total_sector_count <= SECTOR_SIZE // 4

    fat = [FREESECT] * (SECTOR_SIZE // 4)
    fat[0] = FATSECT
    fat[1] = ENDOFCHAIN
    for index in range(stream_sector_count):
        sector = stream_start + index
        fat[sector] = sector + 1 if index + 1 < stream_sector_count else ENDOFCHAIN

    root = _directory_entry('Root Entry', 5, child=1)
    workbook = _directory_entry('Workbook', 2, start=stream_start, size=len(workbook_stream))
    empty = _directory_entry('', 0)
    directory = root + workbook + empty + empty

    header = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'
    header += b'\x00' * 16
    header += struct.pack('<HHHH', 0x003E, 0x0003, 0xFFFE, 0x0009)
    header += struct.pack('<H', 0x0006)
    header += b'\x00' * 6
    header += struct.pack('<IIIIIIIII', 0, 1, 1, 0, 0x1000, ENDOFCHAIN, 0, ENDOFCHAIN, 0)
    header += b''.join(struct.pack('<I', sector) for sector in [0] + [FREESECT] * 108)
    assert len(header) == SECTOR_SIZE

    padded_stream = workbook_stream.ljust(stream_sector_count * SECTOR_SIZE, b'\x00')
    sectors = [b''.join(struct.pack('<I', value) for value in fat), directory]
    sectors.extend(
        padded_stream[offset:offset + SECTOR_SIZE]
        for offset in range(0, len(padded_stream), SECTOR_SIZE)
    )
    assert len(sectors) == total_sector_count

    path.write_bytes(header + b''.join(sectors))


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_formula_record_boundaries(self):
        self.step_name('Test XLM FORMULA records at the BIFF8 size boundary')

        valid_string = b'XLM_VALID_FORMULA'
        testfiles = [
            TC.path_tmp / 'formula-8228.xls',
            TC.path_tmp / 'formula-8227.xls',
            TC.path_tmp / 'formula-100.xls',
            TC.path_tmp / 'formula-21.xls',
            TC.path_tmp / 'formula-8228-truncated-utf16.xls',
            TC.path_tmp / 'formula-8228-truncated-ansi.xls',
            TC.path_tmp / 'formula-8228-truncated-choose.xls',
            TC.path_tmp / 'formula-8228-truncated-extended-function.xls',
            TC.path_tmp / 'formula-22-overdeclared-token-length.xls',
            TC.path_tmp / 'formula-8228-non-macro.xls',
            TC.path_tmp / 'formula-valid-ptgstr.xls',
        ]
        valid_token = b'\x17' + bytes([len(valid_string)]) + b'\x00' + valid_string
        _write_xlm_formula_workbook(testfiles[0], 8228)
        _write_xlm_formula_workbook(testfiles[1], 8227)
        _write_xlm_formula_workbook(testfiles[2], 100)
        _write_xlm_formula_workbook(testfiles[3], 21)
        _write_xlm_formula_workbook(testfiles[4], 8228, token_tail=b'\x17\x01\x01A')
        _write_xlm_formula_workbook(testfiles[5], 8228, token_tail=b'\x17\x02\x00A')
        _write_xlm_formula_workbook(testfiles[6], 8228, token_tail=b'\x19\x40\x00\x00')
        _write_xlm_formula_workbook(testfiles[7], 8228, token_tail=b'\x22\x00\x6d\x80')
        _write_xlm_formula_workbook(testfiles[8], 22, declared_token_length=1)
        _write_xlm_formula_workbook(testfiles[9], 8228, macro_sheet=False)
        _write_xlm_formula_workbook(testfiles[-1], 22 + len(valid_token), token_tail=valid_token)

        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --debug {testfiles}'.format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=TC.path_build / 'unit_tests' / 'input' / 'clamav.hdb',
            testfiles=' '.join(str(path) for path in testfiles),
        )
        output = self.execute_command(command)

        assert output.ec == 0
        self.verify_output(
            output.out,
            expected=['{}: OK'.format(path.name) for path in testfiles],
        )
        assert output.err.count('[cli_extract_xlm_macros_and_images] Extracting macros to') == len(testfiles) - 1

        scanmap_command = '{} {} clean {}'.format(
            TC.check_xlm_scanmap,
            TC.path_build / 'unit_tests' / 'input' / 'clamav.hdb',
            ' '.join(str(path) for path in testfiles),
        )
        scanmap_output = self.execute_command(scanmap_command)

        assert scanmap_output.ec == 0

        signature = TC.path_tmp / 'xlm-formula.ndb'
        signature.write_text(
            'XLM.Formula.ptgStr:0:*:{}\n'.format(
                (b' ptgStr' + valid_string).hex(),
            )
        )

        detection_command = '{valgrind} {valgrind_args} {clamscan} -d {signature} {testfile}'.format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            signature=signature,
            testfile=testfiles[-1],
        )
        detection_output = self.execute_command(detection_command)

        assert detection_output.ec == 1
        self.verify_output(
            detection_output.out,
            expected=['{}: XLM.Formula.ptgStr.UNOFFICIAL FOUND'.format(testfiles[-1].name)],
        )

        scanmap_detection_command = '{} {} virus {}'.format(
            TC.check_xlm_scanmap,
            signature,
            testfiles[-1],
        )
        scanmap_detection_output = self.execute_command(scanmap_detection_command)

        assert scanmap_detection_output.ec == 0
