
// const { Sequelize, DataTypes, Model } = require('sequelize');

module.exports = (sequelize, Sequelize, DataTypes) => {

  const Trip = sequelize.define("trip", {

    // driverName: { type: Sequelize.STRING, allowNull: false },
    phone: { type: Sequelize.STRING, allowNull: false },
    // carNumber: { type: Sequelize.STRING, allowNull: false },
    passengers: { type: Sequelize.STRING, allowNull: false },
    from: { type: Sequelize.STRING, allowNull: false },
    to: { type: Sequelize.STRING, allowNull: false },


    // startTime: { type: Sequelize.STRING, allowNull: false },
    // eArrivalTime: { type: Sequelize.STRING, allowNull: false },
    // startday: { type: Sequelize.STRING, allowNull: false },
    // eArrivalday: { type: Sequelize.STRING, allowNull: false },



    startTimeStamp: { type: Sequelize.BIGINT, allowNull: false },
    endTimeStamp: { type: Sequelize.BIGINT, allowNull: false },


    tirepressure: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    wear: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    walldamage: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    dust: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    wheel: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    spare: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    jack: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    roadside: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    flash: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    engine: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    brake: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    gear: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    clutch: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    washer: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    radiator: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    battery: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    terminals: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    belts: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    fans: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    ac: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    rubber: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    leakage: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    driver: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    vehicle: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    passes: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    fuel: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    scaba: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    extinguishers: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    first: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    seat: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    drinking: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    head: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    back: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    side: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    interior: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    warning: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    brakelights: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    turn: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    reverse: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    windscreen: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    air: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    couplings: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    winch: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    horn: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    secured: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    clean: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    left: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    right: { type: Sequelize.BOOLEAN, defaultValue: 0 },

    notes: { type: Sequelize.STRING, default: '' },

    isApproved: { type: Sequelize.BOOLEAN, defaultValue: 0 },

    isApprovedAt: {
      type:  DataTypes.DATE,
      // defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
      allowNull: true,
    },

    isClosed: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    danger: { type: Sequelize.BOOLEAN, defaultValue: 0 },
    isClosedAt: {
    type:  DataTypes.DATE,
      // defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
      allowNull: true,
    },
  },
    { timestamps: false }
  )

    ;

  return Trip;
};



