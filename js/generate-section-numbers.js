// Section levels for tags h2-h6 (h1 won't be used)
sectionLevelNumbers = [0, 0, 0, 0, 0]

$(':header').each((index, element) => {
  let level = Number(element.nodeName[1]);

  if (level !== 1) {
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

    sectionNumber = sectionNumber.slice(0, -1);

    // Add section-title span around the section title
    $(element).contents().filter(function(){
      return this.nodeType === 3;
    }).wrap('<span class="section-title"></span>');

    // Add in the section number
    $(element).prepend(`<span class="section-num">${sectionNumber}</span>`);

    // Add section id to <section>s
    $(element).parent().prop('id', `section-${sectionNumber.replace(/\./g, '-')}`);
  }
});
