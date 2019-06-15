import React from 'react';
import PropTypes from 'prop-types';
import {Link, Route} from 'react-router-dom';
import {Button} from '../../util/Button/Button';

class NavLink extends React.Component {
    render() {
        return (
            <Route path={this.props.to} children={
                () => {
                    return (
                        <Link to={this.props.to}>
                            <Button minimal icon={this.props.icon} text={this.props.label}/>
                        </Link>
                    );
                }
            }/>
        )
    }
}

NavLink.propTypes = {
    to: PropTypes.oneOfType([PropTypes.string, PropTypes.object]).isRequired,
    icon: PropTypes.oneOfType([PropTypes.string, PropTypes.node]),
    label: PropTypes.string.isRequired
};

export default NavLink;