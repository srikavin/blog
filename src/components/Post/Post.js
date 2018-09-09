import React from 'react';
import PostHeader from './PostHeader/PostHeader'
import PostContent from './PostContent/PostContent';
import {Link} from 'react-router-dom';
import DocumentTitle from 'react-document-title';

import {PostStore} from '../../data/resource/post';
import ErrorState from '../util/ErrorState/ErrorState';
import {FaExclamationTriangle} from 'react-icons/fa';
import styles from './Post.module.css'

class Post extends React.Component {
    constructor(props) {
        super(props);
        this.onPostChange = this.onPostChange.bind(this);

        this.state = {
            error: false,
            loading: true,
            post: {}
        }
    }

    onPostChange(post) {
        if (post.length === 0) {
            this.setState({
                error: true
            })
        }
        this.setState({
            post: post[0] || {},
            loading: false
        });
    }

    componentDidMount() {
        PostStore.getBySlug(this.props.match.params.slug)
            .then(this.onPostChange)
            .catch((e) => {
                console.error(e);
                this.setState({
                    error: true
                })
            });
    }

    render() {
        if (this.state.error) {
            return (
                <div className={styles['post-load-error']}>
                    <ErrorState className={'header'} title={'This post could not be loaded'}
                                description={'There was an error attempting to load this post.'}
                                icon={<FaExclamationTriangle/>}
                                action={<Link to={'/'}>Go home</Link>}/>
                </div>
            )
        }
        return (
            <div>
                {!this.state.loading ? <DocumentTitle title={this.state.post.title}/> : null}
                <PostHeader loading={this.state.loading}
                            className={styles.header}
                            author={this.state.post.author}
                            title={this.state.post.title}
                            tags={this.state.post.tags}
                            createdTime={this.state.post.createdAt}
                            modifiedTime={this.state.post.updatedAt}
                />
                <PostContent content={this.state.post.contents}/>
            </div>
        )
    }
}

export default Post;