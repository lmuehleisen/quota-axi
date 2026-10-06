import { describe, expect, it } from "vitest";
import {
  calendarMonthsBefore,
  clampPercent,
  percentRemaining,
  parseEpochOrIso,
} from "../../src/lib/time.js";

describe("calendarMonthsBefore", () => {
  it("keeps the day and UTC time of day one calendar month earlier", () => {
    expect(calendarMonthsBefore("2026-10-10T07:30:15.250Z", 1)).toBe(
      "2026-09-10T07:30:15.250Z",
    );
  });

  it("clamps the day into a shorter month instead of overflowing", () => {
    expect(calendarMonthsBefore("2026-03-31T00:00:00.000Z", 1)).toBe(
      "2026-02-28T00:00:00.000Z",
    );
    expect(calendarMonthsBefore("2028-03-31T00:00:00.000Z", 1)).toBe(
      "2028-02-29T00:00:00.000Z",
    );
    expect(calendarMonthsBefore("2026-10-31T12:00:00.000Z", 1)).toBe(
      "2026-09-30T12:00:00.000Z",
    );
  });

  it("crosses a year boundary", () => {
    expect(calendarMonthsBefore("2027-01-15T00:00:00.000Z", 1)).toBe(
      "2026-12-15T00:00:00.000Z",
    );
  });

  it("steps back several months", () => {
    expect(calendarMonthsBefore("2027-05-31T00:00:00.000Z", 3)).toBe(
      "2027-02-28T00:00:00.000Z",
    );
    expect(calendarMonthsBefore("2027-05-31T00:00:00.000Z", 12)).toBe(
      "2026-05-31T00:00:00.000Z",
    );
  });

  it("returns undefined for a value that is not a date", () => {
    expect(calendarMonthsBefore("not a date", 1)).toBeUndefined();
  });

  it("returns undefined when the result is not strictly earlier", () => {
    expect(calendarMonthsBefore("2026-10-10T00:00:00.000Z", 0)).toBeUndefined();
  });
});

describe("percentage and timestamp boundaries", () => {
  it.each([99.49, 99.5, 99.9])("preserves fractional %s", (value) => {
    expect(clampPercent(value)).toBe(value);
    expect(percentRemaining(value)).toBe(100 - value);
  });
  it.each([-1, NaN, Infinity, -Infinity])(
    "rejects invalid percentage %s",
    (value) => {
      expect(clampPercent(value)).toBeUndefined();
      expect(percentRemaining(value)).toBeUndefined();
    },
  );
  it("bounds usage above the allowance", () => {
    expect(clampPercent(101)).toBe(100);
    expect(percentRemaining(101)).toBe(0);
  });
  it.each([
    1e20,
    -1e20,
    Number.MAX_VALUE,
    NaN,
    Infinity,
    "not a date",
    "999999-01-01T00:00:00Z",
  ])("rejects reset %s without throwing", (value) => {
    expect(parseEpochOrIso(value)).toBeUndefined();
  });
  it("accepts representable epoch boundaries and ISO instants", () => {
    expect(parseEpochOrIso(0)).toBe("1970-01-01T00:00:00.000Z");
    expect(parseEpochOrIso(8_640_000_000_000)).toBe(
      "+275760-09-13T00:00:00.000Z",
    );
    expect(parseEpochOrIso(-8_640_000_000_000)).toBe(
      "-271821-04-20T00:00:00.000Z",
    );
    expect(parseEpochOrIso("2026-10-06T20:00:00Z")).toBe(
      "2026-10-06T20:00:00.000Z",
    );
  });
});
