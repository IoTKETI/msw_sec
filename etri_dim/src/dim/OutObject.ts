export class OutObject<T> {
  public value: T | null;
  constructor(value?: T) {
    if (value) this.value = value;
    else this.value = null;
  }
}

export class OutByte extends OutObject<number> {}
export class OutByteArray extends OutObject<number[]> {}
export class OutShort extends OutObject<number> {}
export class OutInt extends OutObject<number> {}
