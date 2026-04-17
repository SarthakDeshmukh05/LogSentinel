const fs = require('fs');
const path = require('path');

fetch('https://raw.githubusercontent.com/johan/world.geo.json/master/countries.geo.json')
  .then(r => r.json())
  .then(geo => {
    let paths = '';
    geo.features.forEach(f => {
      if(f.geometry.type === 'Polygon'){
        let d = '';
        f.geometry.coordinates[0].forEach((c,i) => {
          let x = (c[0] + 180) * (800 / 360);
          let y = (90 - c[1]) * (400 / 180);
          d += (i===0?'M':'L') + x + ',' + y;
        });
        d += 'Z';
        paths += '<path d="' + d + '" fill="#1a2942" stroke="#253b5c" stroke-width="0.5"/>';
      } else if(f.geometry.type === 'MultiPolygon'){
        f.geometry.coordinates.forEach(poly => {
          let d = '';
          poly[0].forEach((c,i) => {
            let x = (c[0] + 180) * (800 / 360);
            let y = (90 - c[1]) * (400 / 180);
            d += (i===0?'M':'L') + x + ',' + y;
          });
          d += 'Z';
          paths += '<path d="' + d + '" fill="#1a2942" stroke="#253b5c" stroke-width="0.5"/>';
        });
      }
    });
    const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 400">' + paths + '</svg>';
    fs.writeFileSync(path.join(process.cwd(), 'public', 'world-map.svg'), svg);
    console.log('Saved SVG');
  })
  .catch(e => console.error('Failed to fetch map data', e));
