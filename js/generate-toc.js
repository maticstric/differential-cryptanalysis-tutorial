let tocOl = $('nav#toc > ol');

// previous parent for each h tag level (h2 - h6). Used so you know where to return to if sections go up a level
let previousParent = [tocOl, null, null, null, null]; 
let previousLevel = 2;

$(':header').each((index, element) => {
  let level = Number(element.nodeName[1]);

  for (let i = 2; i <= 6; i++) {
    if (level === i) {
      parent = previousParent[i - 2];

      if (previousLevel === i - 1) {
        let ol = $('<ol></ol>'); 
        previousParent[i - 3].append(ol);
        parent = ol;
      }
    }
  }

  let sectionNum = $(element).html().match('<span class="section-num">.*?</span>')[0];
  let sectionTitle = $(element).html().match('<span class="section-title">.*?</span>')[0];

  let li = $('<li></li>');
  li.append(sectionNum);

  let a = $('<a></a>');
  a.prop('href', `#${$(element).parent().prop('id')}`);
  a.append(sectionTitle);

  li.append(a);

  parent.append(li);

  previousLevel = level;
  previousParent[level - 2] = li;
});
