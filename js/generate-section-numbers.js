// Section levels for tags h2-h6 (h1 won't be used)
sectionLevelNumbers = [0, 0, 0, 0, 0]

$(':header').each((index, element) => {
  let level = Number(element.nodeName[1]);

  for (let i = 2; i <= 6; i++) {
    if (level === i) {
      sectionLevelNumbers[i - 2] += 1;

      for (let j = i - 1; j <= 4; j++) {
        sectionLevelNumbers[j] = 0;
      }
    }
  }

  let sectionNumber = '';

  sectionLevelNumbers.forEach((number) => {
    if (number !== 0) {
      sectionNumber += `${number}.`;
    }
  });

  sectionNumber = sectionNumber.replace(/\.$/g, ' ');

  element.prepend(sectionNumber);
});
