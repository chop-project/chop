extern crate postgres;
use postgres::{Client, NoTls};
pub struct DB {
    // Connection to the database
    pub client: Client,
}

impl DB {
    pub fn new() -> Result<Self, postgres::error::Error> {
        let client = Client::connect(
            "host=localhost user=ubuntu password=exceptionalresearch dbname=exceptionalresearch",
            NoTls,
        )?;

        Ok(Self { client: client })
    }

    #[allow(dead_code)]
    pub fn get_file_name(&mut self, id: i32) -> Result<String, postgres::error::Error> {
        let row = self
            .client
            .query_one("SELECT filename FROM elf_files WHERE id = $1", &[&id])?;

        Ok(row.get::<&str, String>("filename"))
    }

    pub fn get_file_sha256(&mut self, id: i32) -> Result<String, postgres::error::Error> {
        let row = self
            .client
            .query_one("SELECT sha256 FROM elf_files WHERE id = $1", &[&id])?;

        Ok(row.get::<&str, String>("sha256"))
    }

    pub fn write_analysis_data(
        &mut self,
        id: i32,
        analysis_type: i32,
        data: &serde_json::Value,
    ) -> Result<(), postgres::error::Error> {
        let mut transaction = self.client.transaction()?;
        transaction.execute(
            "INSERT INTO analysis (type, file_id, data) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            &[&analysis_type, &id, &data],
        )?;
        transaction.commit()?;

        Ok(())
    }

    pub fn write_null_analysis_data(
        &mut self,
        id: i32,
        analysis_type: i32,
    ) -> Result<(), postgres::error::Error> {
        let mut transaction = self.client.transaction()?;
        transaction.execute(
            "INSERT INTO analysis (type, file_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            &[&analysis_type, &id],
        )?;
        transaction.commit()?;

        Ok(())
    }
}
