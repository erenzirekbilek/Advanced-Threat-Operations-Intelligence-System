import React from "react";
import { simulateAttack } from "../api/api";

const AttackSimulator = () => {
  const handleSimulate = async (type) => {
    const res = await simulateAttack(type);
    alert(`Simülasyon tamamlandı: ${res.type}`);
  };

  return (
    <div>
      <h2>Saldırı Simülasyonu</h2>
      <button onClick={() => handleSimulate("brute_force")}>Brute Force</button>
      <button onClick={() => handleSimulate("sql_injection")}>SQL Injection</button>
    </div>
  );
};

export default AttackSimulator;
