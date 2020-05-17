use std::fmt;

/*
    Memory locations:
    08004D0C - Password encoding routine
    08004D80 - Password decoding routine
    03005040 - Password data
    03005048 - Password length
    03005050 - Password cursor
    03004D84 - Levels bitmask
    03002A08 - Acorns bitmask
    08144D74 - Hardcoded password pointers
    08144D54 - Hardcoded password data
*/

const CHARACTER_SET: &[char; 17] = &[
    'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'V',
];

#[derive(Debug)]
struct SaveData {
    level_bitmask: u16,
    acorn_bitmask: u16,
}

impl SaveData {
    fn is_obtainable(&self) -> bool {
        // TODO: Fix level 10
        let level_order_ok = (self.level_bitmask + 1).is_power_of_two();
        let acorns_ok = self.acorn_bitmask & (self.level_bitmask >> 1) == self.acorn_bitmask;

        level_order_ok && acorns_ok
    }
}

impl fmt::Display for SaveData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[ ")?;
        for i in 0..10 {
            match ((self.level_bitmask >> i) & 1, (self.acorn_bitmask >> i) & 1) {
                (0, 0) => write!(f, "- ")?,
                (1, 0) => write!(f, "x ")?,
                (1, 1) => write!(f, "A ")?,
                (_, _) => write!(f, "? ")?,
            }
        }
        write!(f, "]")?;
        Ok(())
    }
}

fn decode_password(password: &str) -> Result<SaveData, &str> {
    let values: Vec<u32> = password
        .chars()
        .enumerate()
        .map(|(index, pass_char)| {
            CHARACTER_SET
                .iter()
                .position(|&c| c == pass_char)
                .expect("Invalid character") as u32
                + index as u32
        })
        .collect();

    // TODO: Cleanup

    let is_checksum_valid =
        (((((values[1] + values[2] & 0xFF) + values[3] & 0xFF) + values[4] & 0xFF) + values[5])
            * 0x1000000
            & 0xF000000)
            >> 0x18
            == values[0];

    if !is_checksum_valid {
        return Result::Err("Invalid checksum");
    }

    let var_5 = (values[3] - 3 & 0xC) as i32 >> 2;
    let var_2 = (values[1] - 1) * 0x40 | (values[2] - 2) * 4;
    let mut var_1 = false;
    let mut var_3 = 9;

    loop {
        let var_4 = (var_3 * 0x1000000) as i32 >> 0x18;
        if var_4 < 0 {
            break;
        }
        if (((var_2 & 0xFFFF) as i32 | var_5) as i32 >> var_4 & 1) == 0 {
            if var_1 {
                var_1 = false;
                break;
            }
        } else {
            var_1 = true;
        }
        var_3 = var_3 * 0x1000000 - 0x1000000 >> 0x18;
    }

    if var_1 {
        let level_bitmask: u16 = var_2 as u16 | var_5 as u16;
        let acorn_bitmask: u16 = ((values[3] - 3 & 0x03) << 8) as u16
            | (values[4] as u16 - 4) * 0x10
            | values[5] as u16 - 5;
        Result::Ok(SaveData {
            level_bitmask,
            acorn_bitmask,
        })
    } else {
        Result::Err("Invalid password")
    }
}

fn encode_password(save_data: &SaveData) -> String {
    let mut password: [u8; 6] = [0, 0, 0, 0, 0, 0];

    let level = save_data.level_bitmask;
    let acorn = save_data.acorn_bitmask;

    password[1] = 1 + ((level & 0x3C0) >> 6) as u8;
    password[2] = 2 + ((level & 0x03C) >> 2) as u8;
    password[3] = 3 + ((((level & 0x003) << 2) as u8) | ((acorn >> 8) as u8 & 0x003));
    password[4] = 4 + ((acorn & 0x0F0) >> 4) as u8;
    password[5] = 5 + ((acorn & 0x00F) >> 0) as u8;
    password[0] = (password[1] + password[2] + password[3] + password[4] + password[5]) & 0x0F;

    password
        .iter()
        .enumerate()
        .map(|(i, &v)| CHARACTER_SET[v as usize - i])
        .collect()
}

fn main_test_passwords() {
    let tests = &[
        "QBBQBC", "NTTTTT", "NTTTTN", "PBBQBB", "QBCQBB", "SBFQBB", "DBKQBB", "NBTQBB", "PCTQBB",
        "RFTQBB", "CKTQBB", "MTTQBB", "MFKRPH",
    ];

    for test in tests {
        println!("{}: {:?}", test, decode_password(test));
    }
}

fn main_hardcoded_passwords() {
    let hardcoded_password: [&[u8]; 5] = [
        &[0x09, 0x04, 0x09, 0x10, 0x0F, 0x0A], // 08144D54
        &[0x04, 0x03, 0x0E, 0x0B, 0x0D, 0x07], // 08144D5A
        &[0x06, 0x0E, 0x03, 0x06, 0x12, 0x0E], // 08144D60
        &[0x0F, 0x0E, 0x08, 0x03, 0x10, 0x09], // 08144D66
        &[0x0F, 0x0F, 0x0A, 0x0C, 0x07, 0x07], // 08144D6C
    ];

    for hp in hardcoded_password.iter() {
        let password: String = hp
            .iter()
            .enumerate()
            .map(|(index, &value)| CHARACTER_SET[value as usize - index as usize])
            .collect();
        println!("{} -> Art gallery", password);
    }
}

fn main_dump_valid_level_passwords() {
    for level in 1..=10 {
        let level_bitmask = 2u16.pow(level) - 1;

        let acorn_max = if level < 10 {
            2u16.pow(level) >> 1
        } else {
            2u16.pow(level)
        };

        for acorn_bitmask in 0..acorn_max {
            let save_data = SaveData {
                level_bitmask,
                acorn_bitmask,
            };

            println!("{} -> {}", encode_password(&save_data), save_data);
        }
    }
}

fn main() {
    //main_test_passwords();
    main_hardcoded_passwords();
    main_dump_valid_level_passwords();
}
