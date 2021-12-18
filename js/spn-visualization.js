// x positions for ith bit in svg
let xPositions = [90, 110, 130, 150, 210, 230, 250, 270, 330, 350, 370, 390, 450, 470, 490, 510];

const spnHighlightSvgLines = (steps) => {
  // Reset all
  $('#spn-visualization > .figure > svg line').removeClass('isOne');

  let stepsInBinary = steps.map(step => nibblesToBits(step));

  highlightSvgLine('spn-visualization', stepsInBinary[0], 'x');
  highlightSvgLine('spn-visualization', stepsInBinary[1], 'u1');
  highlightSvgLine('spn-visualization', stepsInBinary[2], 'v1');
  highlightSvgLine('spn-visualization', stepsInBinary[4], 'u2');
  highlightSvgLine('spn-visualization', stepsInBinary[5], 'v2');
  highlightSvgLine('spn-visualization', stepsInBinary[7], 'u3');
  highlightSvgLine('spn-visualization', stepsInBinary[8], 'v3');
  highlightSvgLine('spn-visualization', stepsInBinary[10], 'u4');
  highlightSvgLine('spn-visualization', stepsInBinary[11], 'v4');
  highlightSvgLine('spn-visualization', stepsInBinary[12], 'y');
}

const spnShowEncryption = () => {
  let plaintext = $('#spn-visualization > .controls > .plaintext-key-ciphertext .plaintext-input').val();
  let key1 = $('#spn-visualization > .controls > .plaintext-key-ciphertext .key1-input').val();
  let key2 = $('#spn-visualization > .controls > .plaintext-key-ciphertext .key2-input').val();
  let key3 = $('#spn-visualization > .controls > .plaintext-key-ciphertext .key3-input').val();
  let key4 = $('#spn-visualization > .controls > .plaintext-key-ciphertext .key4-input').val();
  let key5 = $('#spn-visualization > .controls > .plaintext-key-ciphertext .key5-input').val();

  // Put everything into the correct format, which is an array of nibbles
  plaintext = plaintext.padStart(4, '0').split('').map(n => parseInt(n, 16));
  key1 = key1.padStart(4, '0').split('').map(n => parseInt(n, 16));
  key2 = key2.padStart(4, '0').split('').map(n => parseInt(n, 16));
  key3 = key3.padStart(4, '0').split('').map(n => parseInt(n, 16));
  key4 = key4.padStart(4, '0').split('').map(n => parseInt(n, 16));
  key5 = key5.padStart(4, '0').split('').map(n => parseInt(n, 16));

  let sbox = getSBOX('spn-visualization');
  if (sbox === null) { return; }
  sbox = sbox.map(n => parseInt(n, 16));

  let pbox = getPBOX('spn-visualization');
  if (pbox === null) { return; }
  pbox = pbox.map(n => parseInt(n, 16));

  let steps = spnEncryptWithSteps(plaintext, sbox, pbox, key1, key2, key3, key4, key5);

  // Show ciphertext in controls
  let ciphertextHex = steps[steps.length - 1].map(n => n.toString(16)).join('');
  $('#spn-visualization > .controls > .plaintext-key-ciphertext .ciphertext-output').text(`0x${ciphertextHex}`);

  // Show ciphertext below svg
  let nibble1 = parseInt(ciphertextHex[0], 16).toString(2).padStart(4, '0');
  let nibble2 = parseInt(ciphertextHex[1], 16).toString(2).padStart(4, '0');
  let nibble3 = parseInt(ciphertextHex[2], 16).toString(2).padStart(4, '0');
  let nibble4 = parseInt(ciphertextHex[3], 16).toString(2).padStart(4, '0');

  $('#spn-visualization > .figure > .ciphertext > .nibble1').text(nibble1);
  $('#spn-visualization > .figure > .ciphertext > .nibble2').text(nibble2);
  $('#spn-visualization > .figure > .ciphertext > .nibble3').text(nibble3);
  $('#spn-visualization > .figure > .ciphertext > .nibble4').text(nibble4);

  spnHighlightSvgLines(steps);
}

$(`#spn-visualization > .controls > .plaintext-key-ciphertext .key1-input,
   #spn-visualization > .controls > .plaintext-key-ciphertext .key2-input,
   #spn-visualization > .controls > .plaintext-key-ciphertext .key3-input,
   #spn-visualization > .controls > .plaintext-key-ciphertext .key4-input,
   #spn-visualization > .controls > .plaintext-key-ciphertext .key5-input`).on('input', (event) => {
  restrictInput(event, 4);

  spnShowEncryption();
});

// Put plaintext from input to top of diagram
$('#spn-visualization > .controls > .plaintext-key-ciphertext .plaintext-input').on('input', (event) => {
  restrictInput(event, 4);
  let value = event.target.value.padStart(4, '0');

  let nibble1 = parseInt(value[0], 16).toString(2).padStart(4, '0');
  let nibble2 = parseInt(value[1], 16).toString(2).padStart(4, '0');
  let nibble3 = parseInt(value[2], 16).toString(2).padStart(4, '0');
  let nibble4 = parseInt(value[3], 16).toString(2).padStart(4, '0');

  $('#spn-visualization > .figure > .plaintext > .nibble1').text(nibble1);
  $('#spn-visualization > .figure > .plaintext > .nibble2').text(nibble2);
  $('#spn-visualization > .figure > .plaintext > .nibble3').text(nibble3);
  $('#spn-visualization > .figure > .plaintext > .nibble4').text(nibble4);

  spnShowEncryption();
});

// Change svg PBOX based on PBOX input
$('#spn-visualization > .controls > .pbox input').on('input', (event) => {
  restrictInput(event, 1);

  let PBOX = getPBOX('spn-visualization');

  if (PBOX !== null) {
    $('#spn-visualization > .controls > .error-messages > .pbox-error').hide();

    for (let i = 0; i < 16; i++) {
      let classSelector = '.pbox.b' + i.toString(16);

      $(classSelector).each((index, element) => {
        element.x2.baseVal.value = xPositions[parseInt(PBOX[i], 16)];
      });
    }

    spnShowEncryption();
  } else {
    $('#spn-visualization > .controls > .error-messages > .pbox-error').show();
  }
});

$('#spn-visualization > .controls > .sbox input').on('input', (event) => {
  restrictInput(event, 1);

  let SBOX = getSBOX('spn-visualization');

  if (SBOX !== null) {
    $('#spn-visualization > .controls > .error-messages > .sbox-error').hide();

    spnShowEncryption();
  } else {
    $('#spn-visualization > .controls > .error-messages > .sbox-error').show();
  }
});

// Show encryption on startup
spnShowEncryption();
