export const hexStrToByteArr = (hexStr: string): number[] => {
  if (hexStr.trim() === "") return [];

  if (hexStr.length % 2 !== 0)
    throw Error("the length of a hex string must be even.");

  hexStr = hexStr.replace(/ /g, "");

  if (hexStr.slice(0, 2).toLowerCase() === "0x")
    hexStr = hexStr.slice(2, hexStr.length);
  const byteArr: number[] = [];
  let i = 0;
  let c = 0;
  let isEmpty = 1;
  let buffer = 0;
  for (i = 0; i < hexStr.length; i++) {
    c = hexStr.charCodeAt(i);
    if ((c > 47 && c < 58) || (c > 64 && c < 71) || (c > 96 && c < 103)) {
      buffer = (buffer << 4) ^ ((c > 64 ? c + 9 : c) & 15);
      if ((isEmpty ^= 1)) {
        byteArr.push(buffer & 0xff);
      }
    } else {
      throw Error("wrong hex string format");
    }
  }
  return byteArr;
};

export const byteArrToHexStr = (byteArr: number[]): string => {
  return Array.from(byteArr, (byte) =>
    `0${(byte & 0xff).toString(16)}`.slice(-2),
  ).join("");
};

export const strToUtf8Arr = (str: string): number[] => {
  const utf8: number[] = [];
  for (let i = 0; i < str.length; i++) {
    let charcode: number = str.charCodeAt(i);
    if (charcode < 0x80) utf8.push(charcode);
    else if (charcode < 0x800) {
      utf8.push(0xc0 | (charcode >> 6), 0x80 | (charcode & 0x3f));
    } else if (charcode < 0xd800 || charcode >= 0xe000) {
      utf8.push(
        0xe0 | (charcode >> 12),
        0x80 | ((charcode >> 6) & 0x3f),
        0x80 | (charcode & 0x3f),
      );
    }
    // surrogate pair
    else {
      i++;
      charcode = ((charcode & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff);
      utf8.push(
        0xf0 | (charcode >> 18),
        0x80 | ((charcode >> 12) & 0x3f),
        0x80 | ((charcode >> 6) & 0x3f),
        0x80 | (charcode & 0x3f),
      );
    }
  }
  return utf8;
};

export const getRandomInt = (max: number): number => {
  return Math.floor(Math.random() * Math.floor(max));
};
