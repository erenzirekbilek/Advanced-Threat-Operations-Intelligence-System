import React, { useEffect, useState } from "react";
import { getCompliance } from "../api/api";

const ComplianceStatus = () => {
  const [compliance, setCompliance] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      const data = await getCompliance();
      setCompliance(data);
    };
    fetchData();
  }, []);

  return (
    <div>
      <h2>Uyumluluk Durumu</h2>
      <ul>
        {compliance.map((c, idx) => (
          <li key={idx}>
            <strong>{c.standard}</strong> - Skor: {c.score} - Durum: {c.status}
          </li>
        ))}
      </ul>
    </div>
  );
};

export default ComplianceStatus;
