import React, { useEffect, useState } from "react";
import { getThreats } from "../api/api";

const ThreatList = () => {
  const [threats, setThreats] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      const data = await getThreats();
      setThreats(data);
    };
    fetchData();
  }, []);

  return (
    <div>
      <h2>Tehdit Listesi</h2>
      <table border="1" cellPadding="5">
        <thead>
          <tr>
            <th>ID</th>
            <th>Tip</th>
            <th>Şiddet</th>
            <th>Kaynak IP</th>
            <th>Zaman</th>
            <th>Durum</th>
          </tr>
        </thead>
        <tbody>
          {threats.map((t) => (
            <tr key={t.id}>
              <td>{t.id}</td>
              <td>{t.type}</td>
              <td>{t.severity}</td>
              <td>{t.source}</td>
              <td>{new Date(t.time).toLocaleString()}</td>
              <td>{t.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default ThreatList;
